// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
// protobuf-codegen-pure would generate warnings
#![allow(elided_lifetimes_in_paths)]

mod backend;
mod cli;
mod exec;

#[cfg(enarx_with_shim)]
mod protobuf;

use backend::{Backend, Command};
use cli::{deploy, run};
use exec::EXECS;

use std::borrow::Borrow;
use std::fs::{self, File};
use std::io::Write;
use std::iter::empty;
use std::net::Shutdown;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use enarx_exec_wasmtime::{Args, Package, PACKAGE_CONFIG, PACKAGE_ENTRYPOINT};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use log::info;
#[cfg(enarx_with_shim)]
use mmarinus::{perms, Map, Private};

/// Tool to deploy WebAssembly into Enarx Keeps
///
/// Enarx is a tool for running Webassembly inside an Enarx Keep
/// - that is a hardware isolated environment using technologies
/// such as Intel SGX or AMD SEV.
///
/// For more information about the project and the technology used
/// visit the Enarx Project home page https://enarx.dev/.
#[derive(Parser, Debug)]
#[clap(version)]
struct Options {
    /// Logging options
    #[clap(flatten)]
    log: cli::LogOptions,

    /// Subcommands (with their own options)
    #[clap(subcommand)]
    cmd: cli::Command,
}

/// Write timeout for writing the arguments to exec-wasmtime.
const ARG_WRITE_TIMEOUT: Duration = Duration::new(60, 0);

fn open_package(
    wasm: impl Borrow<PathBuf>,
    conf: Option<impl Borrow<PathBuf>>,
) -> Result<(File, Option<File>)> {
    let wasm = wasm.borrow();
    let wasm = File::open(wasm)
        .with_context(|| format!("failed to open WASM module at `{}`", wasm.display()))?;
    if let Some(conf) = conf {
        let conf = conf.borrow();
        let conf = File::open(conf)
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
fn run_package<I: Iterator<Item = File>>(
    backend: &dyn Backend,
    exec: impl AsRef<[u8]>,
    gdblisten: Option<String>,
    package: impl FnOnce() -> Result<(Package, I)>,
) -> Result<i32> {
    let (exec_sock, mut host_sock) =
        UnixStream::pair().context("failed to create a Unix socket pair")?;

    assert_eq!(
        exec_sock.as_raw_fd(),
        3, // The first free FD after STDOUT, STDIN and STDERR are assigned.
        "exec-wasmtime expects the Unix socket to be at FD 3"
    );

    let (package, _files) = package()?;
    let args =
        toml::to_vec(&Args { package }).context("failed to encode exec-wasmtime arguments")?;

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

    let exit_code = keep_exec(backend, backend.shim(), exec, gdblisten)?;
    exec_io
        .join()
        .expect("failed to join exec-wasmtime I/O thread")?;
    Ok(exit_code)
}

fn main() -> Result<()> {
    let opts = Options::parse();
    opts.log.init_logger();

    info!("logging initialized!");
    info!("CLI opts: {:?}", &opts);

    match opts.cmd {
        cli::Command::Info(info) => info.display(),
        #[cfg(not(enarx_with_shim))]
        cli::Command::Exec(_) => {
            anyhow::bail!("exec option not supported")
        }
        #[cfg(enarx_with_shim)]
        cli::Command::Exec(exec) => {
            let backend = exec.backend.pick()?;
            let binary = Map::load(&exec.binpath, Private, perms::Read)?;

            #[cfg(not(feature = "gdb"))]
            let gdblisten = None;

            #[cfg(feature = "gdb")]
            let gdblisten = Some(exec.gdblisten);

            let exit_code = keep_exec(backend, backend.shim(), binary, gdblisten)?;
            std::process::exit(exit_code);
        }
        cli::Command::Run(run::Options {
            backend,
            wasmcfgfile,
            module,
            #[cfg(feature = "gdb")]
            gdblisten,
        }) => {
            let backend = backend.pick()?;
            let exec = EXECS
                .iter()
                .find(|w| w.with_backend(backend))
                .ok_or_else(|| anyhow!("no supported exec found"))
                .map(|b| b.exec())?;
            let code = run_package(
                backend,
                exec,
                #[cfg(not(feature = "gdb"))]
                None,
                #[cfg(feature = "gdb")]
                Some(gdblisten),
                || {
                    let (wasm, conf) = open_package(module, wasmcfgfile)?;
                    Ok((
                        Package::Local {
                            wasm: wasm.as_raw_fd(),
                            conf: conf.as_ref().map(|conf| conf.as_raw_fd()),
                        },
                        vec![wasm].into_iter().chain(conf),
                    ))
                },
            )?;
            std::process::exit(code);
        }
        cli::Command::Deploy(deploy::Options {
            backend,
            package,
            #[cfg(feature = "gdb")]
            gdblisten,
        }) => {
            let backend = backend.pick()?;
            // TODO: Only allow secure backends
            // https://github.com/enarx/enarx/issues/1850
            let exec = EXECS
                .iter()
                .find(|w| w.with_backend(backend))
                .ok_or_else(|| anyhow!("no supported exec found"))
                .map(|b| b.exec())?;

            #[cfg(not(feature = "gdb"))]
            let gdblisten = None;

            #[cfg(feature = "gdb")]
            let gdblisten = Some(gdblisten);

            let code = match package.scheme() {
                "file" => {
                    let path = package.to_file_path().map_err(|()| {
                        anyhow!("failed to parse file path from URL `{}`", package)
                    })?;
                    let md = fs::metadata(&path).with_context(|| {
                        format!("failed to get information about `{}`", path.display())
                    })?;
                    let (wasm, conf) = if md.is_file() {
                        (path, None)
                    } else if md.is_dir() {
                        (
                            path.join(PACKAGE_ENTRYPOINT),
                            Some(path.join(PACKAGE_CONFIG)),
                        )
                    } else {
                        bail!(
                            "no Enarx package or WASM module found at `{}`",
                            path.display()
                        )
                    };
                    run_package(backend, exec, gdblisten, || {
                        let (wasm, conf) = open_package(wasm, conf)?;
                        Ok((
                            Package::Local {
                                wasm: wasm.as_raw_fd(),
                                conf: conf.as_ref().map(|conf| conf.as_raw_fd()),
                            },
                            vec![wasm].into_iter().chain(conf),
                        ))
                    })?
                }

                // The WASM module and config will be downloaded from a remote by exec-wasmtime
                // TODO: Disallow `http` or guard by an `--insecure` flag
                "http" | "https" => run_package(backend, exec, gdblisten, || {
                    Ok((Package::Remote(package), empty()))
                })?,

                s => bail!("unsupported scheme: {}", s),
            };
            std::process::exit(code);
        }
        #[cfg(enarx_with_shim)]
        cli::Command::Snp(cmd) => cli::snp::run(cmd),
        #[cfg(enarx_with_shim)]
        cli::Command::Sgx(cmd) => cli::sgx::run(cmd),
    }
}

fn keep_exec(
    backend: &dyn Backend,
    shim: impl AsRef<[u8]>,
    exec: impl AsRef<[u8]>,
    _gdblisten: Option<String>,
) -> Result<libc::c_int> {
    let keep = backend.keep(shim.as_ref(), exec.as_ref())?;
    let mut thread = keep.clone().spawn()?.unwrap();
    loop {
        match thread.enter(&_gdblisten)? {
            Command::Continue => (),
            Command::Exit(exit_code) => return Ok(exit_code),
        }
    }
}
