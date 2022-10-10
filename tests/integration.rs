// SPDX-License-Identifier: Apache-2.0

#![cfg(all(not(miri), not(feature = "gdb")))]

extern crate core;

#[cfg(not(windows))]
mod client;

#[cfg(enarx_with_shim)]
mod exec;

#[cfg(enarx_with_shim)]
mod syscall;

mod wasm;

use std::ffi::{OsStr, OsString};
use std::io;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time;

use process_control::{ChildExt, Control, Output};
use tempfile::tempdir;

pub const CRATE: &str = env!("CARGO_MANIFEST_DIR");
pub const KEEP_BIN: &str = env!("CARGO_BIN_EXE_enarx");
pub const OUT_DIR: &str = env!("OUT_DIR");
pub const TEST_BINS_OUT: &str = "bin";
pub const TIMEOUT_SECS: u64 = 60 * 60;
pub const MAX_ASSERT_ELEMENTS: usize = 100;

pub fn assert_eq_slices(expected_output: &[u8], output: &[u8], what: &str) {
    let max_len = usize::min(output.len(), expected_output.len());
    let max_len = max_len.min(MAX_ASSERT_ELEMENTS);
    assert_eq!(
        output[..max_len],
        expected_output[..max_len],
        "Expected contents of {} differs",
        what
    );

    assert_eq!(
        output.len(),
        expected_output.len(),
        "Expected length of {} differs",
        what,
    );

    assert_eq!(
        output, expected_output,
        "Expected contents of {} differs",
        what
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
    .unwrap_or_else(|e| panic!("failed to execute command: {:#?}", e));

    let stdin = input.into().map(|input| {
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
        std::thread::spawn(move || {
            stdin
                .write_all(&input)
                .expect("failed to write stdin to child");
        })
    });
    let stderr = {
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(|| tee(stderr, io::stderr()).expect("failed to copy stderr"))
    };

    let mut output = child
        .controlled_with_output()
        .time_limit(time::Duration::from_secs(TIMEOUT_SECS))
        .terminate_for_timeout()
        .wait()
        .unwrap_or_else(|e| panic!("failed to run command: {:#?}", e))
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
