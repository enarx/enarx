// SPDX-License-Identifier: Apache-2.0

#![cfg(all(not(miri), not(feature = "gdb")))]

extern crate core;

#[cfg(not(windows))]
mod client;

#[cfg(any(host_can_test_kvm, host_can_test_sev, host_can_test_sgx))]
mod exec;

#[cfg(any(host_can_test_kvm, host_can_test_sev, host_can_test_sgx))]
mod syscall;

mod wasm;

use std::cmp::min;
use std::env::{var, VarError};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufReader, LineWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use process_control::{ChildExt, Control, Output};
use tempfile::tempdir;

pub const CRATE: &str = env!("CARGO_MANIFEST_DIR");
pub const KEEP_BIN: &str = env!("CARGO_BIN_EXE_enarx");
pub const OUT_DIR: &str = env!("OUT_DIR");
pub const TEST_BINS_OUT: &str = "bin";
pub const TIMEOUT_SECS: u64 = 60 * 60;
pub const MAX_ASSERT_ELEMENTS: usize = 100;

/// `ENARX_BACKEND` environment variable value
pub static ENARX_BACKEND: Lazy<Option<String>> = Lazy::new(|| match var("ENARX_BACKEND") {
    Ok(backend) => Some(backend),
    Err(VarError::NotUnicode(..)) => panic!("`ENARX_BACKEND` value is not valid unicode"),
    Err(VarError::NotPresent) => None,
});

/// Returns `true` if SGX backend should be used by Enarx given the environment
pub fn is_sgx() -> bool {
    match ENARX_BACKEND.as_deref() {
        Some("sgx") => true,
        Some(..) => false,
        None => cfg!(host_can_test_sgx),
    }
}

/// Returns `true` if SEV backend should be used by Enarx given the environment
pub fn is_sev() -> bool {
    match ENARX_BACKEND.as_deref() {
        Some("sev") => true,
        Some(..) => false,
        // NOTE: SGX backend is prioritized
        None => cfg!(host_can_test_sev) && !is_sgx(),
    }
}

/// Returns `true` if KVM backend should be used by Enarx given the environment
pub fn is_kvm() -> bool {
    match ENARX_BACKEND.as_deref() {
        Some("kvm") => true,
        Some(..) => false,
        None => cfg!(host_can_test_kvm) && !is_sgx() && !is_sev(),
    }
}

/// Returns `true` if nil backend should be used by Enarx given the environment
pub fn is_nil() -> bool {
    match ENARX_BACKEND.as_deref() {
        Some("nil") => true,
        Some(..) => false,
        None => !is_sgx() && !is_sev() && !is_kvm(),
    }
}

/// Best-effort on-disk mutex lock.
/// Mutually-exclusive access it not guaranteed in cases when previous invocation did not exit cleanly.
pub struct PathLock(PathBuf);

impl From<PathBuf> for PathLock {
    fn from(path: PathBuf) -> Self {
        Self(path)
    }
}

impl PathLock {
    /// Initialize a new [`PathLock`] called `name` within `OUT_DIR`.
    pub fn new_in_out_dir(name: impl AsRef<Path>) -> Self {
        Path::new(OUT_DIR).join(name).into()
    }

    /// Acquire lock at associated path for duration of `ttl`.
    ///
    /// If lock is already held by another thread for more than `ttl`, then it will be
    /// considered stale and reacquired on a best-effort basis.
    fn lock(&self, ttl: Duration) -> io::Result<impl Drop + '_> {
        let start = Instant::now();
        match fs::File::options()
            .write(true)
            .create_new(true)
            .open(&self.0)
        {
            Ok(_) => {} // Lock acquired
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let sleep_duration = min(Duration::from_millis(100), ttl / 10);

                let elapsed = self.0.metadata()?.modified()?.elapsed().expect(
                    "failed to compute time elapsed since lock was acquired by another thread",
                );
                if elapsed < ttl {
                    // Another thread had already acquired the lock within `ttl`, wait for it
                    // to be released and return `io::ErrorKind::AlreadyExists` if it is
                    while start.elapsed() < ttl && self.0.exists() {
                        thread::sleep(sleep_duration);
                    }
                    if !self.0.exists() {
                        return Err(e);
                    }
                }

                // Previous lock has timed out, probably because thread holding it crashed without unlocking
                match self.unlock() {
                    Ok(()) => {
                        eprintln!(
                            "possibly stale lock at `{}` removed (this is prone to a race condition)",
                            self.0.display()
                        );
                        // We managed to remove the lock and assume we acquired mutex access.
                        // This is prone to race condition, where another thread could call
                        // `lock` with a "fresh" state, create the file and one of the other
                        // previously blocked threads could remove it.
                        // Sleep for `ttl` to allow for (most) other blocked threads to exit
                        let start = Instant::now(); // Reset starting time
                        while start.elapsed() < ttl {
                            if self.0.exists() {
                                // Another thread started "fresh" and locked, return
                                // original `io::ErrorKind::AlreadyExists` error
                                return Err(e);
                            }
                            thread::sleep(sleep_duration);
                        }
                        // Retry after `ttl`
                        return self.lock(ttl);
                    }
                    Err(unlock_err) if unlock_err.kind() == io::ErrorKind::NotFound => {
                        // another thread has already unlocked the lock, return original
                        // `io::ErrorKind::AlreadyExists` error
                        eprintln!(
                            "stale lock at `{}` already reacquired by another thread",
                            self.0.display()
                        );
                        return Err(e);
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }

        struct Guard<'a>(&'a PathLock);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                self.0.unlock().unwrap_or_else(|e| {
                    eprintln!("failed to remove lock at `{}`: {e}", self.0 .0.display())
                })
            }
        }

        Ok(Guard(self))
    }

    /// Release the lock.
    fn unlock(&self) -> io::Result<()> {
        fs::remove_file(&self.0)
    }

    /// Calls `f` once if `pred` returns `true`.
    ///
    /// `ttl` represents the lock time-to-live. A lock will be considered stale and reacquired
    /// if older than `ttl`.
    ///
    /// Returns:
    /// - `Ok(Some(..))` if `f` was called
    /// - `Ok(None)` if `pred` returned false
    /// - `Err(e)` if either locking failed due to an I/O error
    pub fn once_if<T>(
        &self,
        pred: impl Fn() -> bool,
        f: impl FnOnce() -> T,
        ttl: Duration,
    ) -> io::Result<Option<T>> {
        while pred() {
            match self.lock(ttl) {
                Ok(_) if !pred() => return Ok(None), // another thread managed to lock first
                Ok(_) => return Ok(Some(f())), // lock acquired and `pred()` is still `true`, call `f()`
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e), // I/O failure
            }
        }
        Ok(None)
    }
}

pub fn assert_eq_slices(expected_output: &[u8], output: &[u8], what: &str) {
    let max_len = usize::min(output.len(), expected_output.len());
    let max_len = max_len.min(MAX_ASSERT_ELEMENTS);
    assert_eq!(
        output[..max_len],
        expected_output[..max_len],
        "Expected contents of {what} differs"
    );

    assert_eq!(
        output.len(),
        expected_output.len(),
        "Expected length of {what} differs",
    );

    assert_eq!(
        output, expected_output,
        "Expected contents of {what} differs"
    );
}

fn tee(r: impl Read, mut w: impl Write) -> io::Result<Vec<u8>> {
    BufReader::new(r)
        .bytes()
        .map(|b| {
            let b = b?;
            w.write_all(&[b])?;
            Ok(b)
        })
        .collect()
}

fn enarx<'a>(
    cmd: impl FnOnce(&mut Command) -> &mut Command,
    input: impl Into<Option<&'a [u8]>>,
) -> Output {
    let mut child = cmd(Command::new(KEEP_BIN)
        .current_dir(CRATE)
        .env(
            "ENARX_TEST_SGX_KEY_FILE",
            CRATE.to_string() + "/tests/data/sgx-test.key",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()))
    .spawn()
    .unwrap_or_else(|e| panic!("failed to execute command: {e:#?}"));

    let stdin = input.into().map(|input| {
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
        thread::spawn(move || {
            stdin
                .write_all(&input)
                .expect("failed to write stdin to child");
        })
    });
    let stderr = {
        let stderr = child.stderr.take().unwrap();
        thread::spawn(|| tee(stderr, LineWriter::new(io::stderr())).expect("failed to copy stderr"))
    };

    let mut output = child
        .controlled_with_output()
        .time_limit(Duration::from_secs(TIMEOUT_SECS))
        .terminate_for_timeout()
        .wait()
        .unwrap_or_else(|e| panic!("failed to run command: {e:#?}"))
        .unwrap_or_else(|| panic!("process timed out"));

    if let Some(stdin) = stdin {
        stdin.join().expect("failed to provide input for process");
    }
    output.stderr = stderr.join().expect("failed to collect stderr");

    #[cfg(unix)]
    assert!(
        output.status.code().is_some(),
        "process terminated by signal {:?}",
        output.status.signal()
    );

    output
}

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
pub fn keepldr_exec_signed<'a>(
    bin: impl Into<PathBuf>,
    input: impl Into<Option<&'a [u8]>>,
) -> Output {
    let tmpdir = tempdir().expect("failed to create temporary package directory");
    let signature_file_path = tmpdir.path().join("sig.json");
    let binpath: OsString = bin.into().into_os_string();

    let out = enarx(
        |cmd| {
            cmd.args(vec![
                OsStr::new("sign"),
                &binpath,
                OsStr::new("--sgx-key"),
                OsStr::new("tests/data/sgx-test.key"),
                OsStr::new("--sev-id-key"),
                OsStr::new("tests/data/sev-id.key"),
                OsStr::new("--sev-id-key-signature"),
                OsStr::new("tests/data/sev-id-key-signature.blob"),
                OsStr::new("--out"),
                signature_file_path.as_os_str(),
            ])
        },
        None,
    );

    if !out.status.success() {
        eprintln!(
            "failed to sign package: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return out;
    }
    let res = enarx(
        |cmd| {
            cmd.args(vec![
                OsStr::new("unstable"),
                OsStr::new("exec"),
                OsStr::new("--signatures"),
                signature_file_path.as_os_str(),
                &binpath,
            ])
        },
        input,
    );

    tmpdir.close().unwrap();

    res
}

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
pub fn keepldr_exec<'a>(bin: impl Into<PathBuf>, input: impl Into<Option<&'a [u8]>>) -> Output {
    enarx(
        |cmd| {
            cmd.args(vec![
                OsStr::new("unstable"),
                OsStr::new("exec"),
                OsStr::new("--unsigned"),
                bin.into().as_os_str(),
            ])
        },
        input,
    )
}

pub fn check_output<'a>(
    output: &Output,
    expected_status: i32,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) {
    let expected_stdout = expected_stdout.into();
    let expected_stderr = expected_stderr.into();

    if let Some(expected_stdout) = expected_stdout {
        if output.stdout.len() < MAX_ASSERT_ELEMENTS && expected_stdout.len() < MAX_ASSERT_ELEMENTS
        {
            assert_eq!(
                output.stdout, expected_stdout,
                "Expected contents of stdout output differs"
            );
        } else {
            assert_eq_slices(expected_stdout, &output.stdout, "stdout output");
        }
    }

    if let Some(expected_stderr) = expected_stderr {
        if output.stderr.len() < MAX_ASSERT_ELEMENTS && expected_stderr.len() < MAX_ASSERT_ELEMENTS
        {
            assert_eq!(
                output.stderr, expected_stderr,
                "Expected contents of stderr output differs."
            );
        } else {
            assert_eq_slices(expected_stderr, &output.stderr, "stderr output");
        }
    }

    assert_eq!(
        output.status.code().unwrap(),
        expected_status as i64,
        "Expected exit status differs."
    );
}

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
pub fn run_test<'a>(
    bin: impl Into<PathBuf>,
    status: i32,
    input: impl Into<Option<&'a [u8]>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) -> Output {
    let output = keepldr_exec(bin, input);
    check_output(&output, status, expected_stdout, expected_stderr);
    output
}

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
pub fn run_test_signed<'a>(
    bin: impl Into<PathBuf>,
    status: i32,
    input: impl Into<Option<&'a [u8]>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) -> Output {
    let output = keepldr_exec_signed(bin, input);
    check_output(&output, status, expected_stdout, expected_stderr);
    output
}
