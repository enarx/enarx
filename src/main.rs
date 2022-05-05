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

#[cfg(feature = "backend-sgx")]
mod protobuf;

use backend::{Backend, Command};
use enarx_exec_wasmtime::{Args, Package};
#[cfg(feature = "load-binary")]
use mmarinus::{perms, Map, Private};

use std::fs::{self, File};
use std::io::Write;
use std::net::Shutdown;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use log::info;

use crate::cli::run;
use crate::exec::EXECS;

// This defines the toplevel `enarx` CLI
#[derive(Parser, Debug)]
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

fn main() -> Result<()> {
    let opts = Options::parse();
    opts.log.init_logger();

    info!("logging initialized!");
    info!("CLI opts: {:?}", &opts);

    match opts.cmd {
        cli::Command::Info(info) => info.display(),
        #[cfg(not(feature = "load-binary"))]
        cli::Command::Exec(_) => {
            anyhow::bail!("exec option not supported")
        }
        #[cfg(feature = "load-binary")]
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
            package,
            steward,
            #[cfg(feature = "gdb")]
            gdblisten,
        }) => {
            let backend = backend.pick()?;
            let exec = EXECS
                .deref()
                .iter()
                .find(|w| w.with_backend(backend))
                .ok_or_else(|| anyhow!("no supported exec found"))
                .map(|b| b.exec())?;

            let (exec_sock, mut host_sock) =
                UnixStream::pair().context("failed to create a Unix socket pair")?;
            assert_eq!(exec_sock.as_raw_fd(), 3);
            assert_eq!(host_sock.as_raw_fd(), 4);

            let (package, wasm, conf) = match package.scheme() {
                "file" => {
                    let path = package.to_file_path().map_err(|()| {
                        anyhow!("failed to parse file path from URL `{}`", package)
                    })?;
                    match fs::metadata(&path).with_context(|| {
                        format!(
                            "failed to get information about `{}`",
                            path.to_string_lossy(),
                        )
                    })? {
                        md if md.is_file() => {
                            let wasm = File::open(path)?;
                            (
                                Package::Local {
                                    wasm: wasm.as_raw_fd(),
                                    conf: None,
                                },
                                Some(wasm),
                                None,
                            )
                        }
                        md if md.is_dir() => {
                            let wasm = File::open(path.join("main.wasm")).with_context(|| {
                                format!(
                                    "failed to open `main.wasm` within `{}`",
                                    path.to_string_lossy()
                                )
                            })?;
                            let conf = File::open(path.join("Enarx.toml")).with_context(|| {
                                format!(
                                    "failed to open `Enarx.toml` within `{}`",
                                    path.to_string_lossy()
                                )
                            })?;
                            (
                                Package::Local {
                                    wasm: wasm.as_raw_fd(),
                                    conf: Some(conf.as_raw_fd()),
                                },
                                Some(wasm),
                                Some(conf),
                            )
                        }
                        _ => bail!(
                            "no Enarx package or WASM module found at `{}`",
                            path.to_string_lossy()
                        ),
                    }
                }
                // The workload and config will be downloaded from a remote by exec-wasmtime
                "http" | "https" => (Package::Remote(package), None, None),

                s => bail!("unsupported scheme: {}", s),
            };
            let args = toml::to_vec(&Args { package, steward })
                .context("failed to encode exec-wasmtime arguments")?;

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

            #[cfg(not(feature = "gdb"))]
            let gdblisten = None;

            #[cfg(feature = "gdb")]
            let gdblisten = Some(gdblisten);

            let exit_code = keep_exec(backend, backend.shim(), exec, gdblisten)?;
            exec_io
                .join()
                .expect("failed to join exec-wasmtime I/O thread")?;
            drop(exec_sock);
            if let Some(wasm) = wasm {
                drop(wasm)
            }
            if let Some(conf) = conf {
                drop(conf)
            }
            std::process::exit(exit_code);
        }
        #[cfg(feature = "backend-sev")]
        cli::Command::Snp(cmd) => cli::snp::run(cmd),
        #[cfg(feature = "backend-sgx")]
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
