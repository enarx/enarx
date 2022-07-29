// SPDX-License-Identifier: Apache-2.0

// FUTURE: right now we only have one exec, `enarx-exec-wasmtime`.
// In the future there may be other workload types - in theory we can run
// any static PIE ELF binary. We could have a Lua interpreter, or a
// JavaScript interpreter, or whatever.
// So there's two parts to this trait - call them KeepSetup and Engine.
//
// KeepSetup is the part that actually sets up the Keep for the Workload,
// which might involve setting up network sockets, storage devices, etc.
// This part must be implemented by any Exec, since we want the
// Enarx environment to be platform-agnostic.
//
// Engine is the (exec-specific) portion that actually interprets or
// executes the workload. It's responsible for taking the sockets / devices
// etc. that were set up by KeepSetup and making them usable in a way that
// the workload will understand.
//
// So: someday we might want to split this into two traits, and we might
// have multiple Execs for different languages/environments, and we
// might need to examine the workload and determine which Exec is
// the right one to use. But first... we gotta make exec-wasmtime work.

#[cfg(enarx_with_shim)]
pub mod exec_wasmtime;

use crate::backend::{Backend, Command, Signatures};

use std::convert::Into;
use std::fs::File;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

use anyhow::{Context, Result};
use enarx_exec_wasmtime::{Args as ExecArgs, Package};
use once_cell::sync::Lazy;

/// Write timeout for writing the arguments to exec-wasmtime.
#[cfg(unix)]
const ARG_WRITE_TIMEOUT: Duration = Duration::new(60, 0);

/// A trait for the "Exec"
///
/// (as in Backend::keep(shim, exec) [q.v.]) and formerly known as the "code"
/// layer. This is the part that runs inside the keep, prepares the workload
/// environment, and then actually executes the tenant's workload.
///
/// Basically, this is a generic view of exec_wasmtime.
pub trait Exec: Sync + Send {
    /// The name of the executable
    fn name(&self) -> &'static str;

    /// The executable (e.g. exec_wasmtime)
    fn exec(&self) -> &'static [u8];

    /// Picks a suitable executable for the backend
    ///
    /// E.g. in case of the `nil` backend it will pick the `NilExec`,
    /// which calls into the `exec-wasmtime` crate directly, without
    /// loading any binary.
    fn with_backend(&self, backend: &dyn Backend) -> bool;
}

pub struct NilExec;

impl Exec for NilExec {
    fn name(&self) -> &'static str {
        "nil"
    }

    fn exec(&self) -> &'static [u8] {
        &[]
    }

    fn with_backend(&self, backend: &dyn Backend) -> bool {
        backend.name() == "nil"
    }
}

pub static EXECS: Lazy<Vec<Box<dyn Exec>>> = Lazy::new(|| {
    vec![
        #[cfg(enarx_with_shim)]
        Box::new(exec_wasmtime::WasmExec),
        Box::new(NilExec),
    ]
});

pub fn keep_exec(
    backend: &dyn Backend,
    shim: impl AsRef<[u8]>,
    exec: impl AsRef<[u8]>,
    signatures: Option<Signatures>,
    _gdblisten: Option<String>,
) -> anyhow::Result<libc::c_int> {
    let keep = backend.keep(shim.as_ref(), exec.as_ref(), signatures)?;
    let mut thread = keep.clone().spawn()?.unwrap();
    loop {
        match thread.enter(&_gdblisten)? {
            Command::Continue => (),
            Command::Exit(exit_code) => return Ok(exit_code),
        }
    }
}

pub fn open_package(
    wasm: impl Into<PathBuf>,
    conf: Option<impl Into<PathBuf>>,
) -> Result<(File, Option<File>)> {
    let wasm = wasm.into();
    let wasm = File::open(&wasm)
        .with_context(|| format!("failed to open WASM module at `{}`", wasm.display()))?;
    if let Some(conf) = conf {
        let conf = conf.into();
        let conf = File::open(&conf)
            .with_context(|| format!("failed to open package config at `{}`", conf.display()))?;
        Ok((wasm, Some(conf)))
    } else {
        Ok((wasm, None))
    }
}

/// Runs a package.
/// SAFETY: Panics if next free FD number is not equal to 3.
/// In other words, callers must either close all files opened at runtime before calling this
/// function or ensure that no such operations have taken place.
#[cfg(windows)]
pub fn run_package(
    backend: &dyn Backend,
    exec: impl AsRef<[u8]>,
    _signatures: Option<Signatures>,
    gdblisten: Option<String>,
    package: impl FnOnce() -> Result<Package>,
) -> Result<i32> {
    let package = package()?;
    let args = ExecArgs { package };
    backend.set_args(args);
    let exit_code = keep_exec(backend, backend.shim(), exec, None, gdblisten)?;
    Ok(exit_code)
}

/// Runs a package.
/// SAFETY: Panics if next free FD number is not equal to 3.
/// In other words, callers must either close all files opened at runtime before calling this
/// function or ensure that no such operations have taken place.
#[cfg(unix)]
pub fn run_package(
    backend: &dyn Backend,
    exec: impl AsRef<[u8]>,
    signatures: Option<Signatures>,
    gdblisten: Option<String>,
    package: impl FnOnce() -> Result<Package>,
) -> Result<i32> {
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::thread;

    let (exec_sock, mut host_sock) =
        UnixStream::pair().context("failed to create a Unix socket pair")?;

    assert_eq!(
        exec_sock.as_raw_fd(),
        3, // The first free FD after STDOUT, STDIN and STDERR are assigned.
        "exec-wasmtime expects the Unix socket to be at FD 3"
    );

    let package = package()?;
    let args =
        toml::to_vec(&ExecArgs { package }).context("failed to encode exec-wasmtime arguments")?;

    host_sock
        .set_nonblocking(true)
        .context("failed to set host socket to non-blocking")?;
    host_sock
        .set_write_timeout(Some(ARG_WRITE_TIMEOUT))
        .context("failed to set timeout on host socket")?;

    let exec_io = thread::spawn(move || {
        host_sock
            .write_all(&args)
            .context("failed to write arguments to `wasmtime-exec`")?;
        host_sock
            .shutdown(Shutdown::Write)
            .context("failed to shutdown write half of host's socket")?;
        // TODO: Read exec-wasmtime output from the socket
        host_sock
            .shutdown(Shutdown::Read)
            .context("failed to shutdown read half of host's socket")
    });

    let exit_code = keep_exec(backend, backend.shim(), exec, signatures, gdblisten)?;
    exec_io
        .join()
        .expect("failed to join exec-wasmtime I/O thread")?;
    Ok(exit_code)
}

#[cfg(test)]
mod test {
    use super::{Exec, NilExec};

    #[test]
    fn coverage() {
        let exec = NilExec;
        assert_eq!(exec.name(), "nil");
        assert!(exec.exec().is_empty());
    }
}
