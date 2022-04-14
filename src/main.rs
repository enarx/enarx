// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
// protobuf-codegen-pure would generate warnings
#![allow(elided_lifetimes_in_paths)]

mod backend;
mod cli;
mod protobuf;
mod workldr;

use backend::{Backend, Command};

use std::fs::File;
use std::os::unix::io::AsRawFd;

use anyhow::Result;
use clap::Parser;
use log::info;

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

fn main() -> Result<()> {
    let opts = Options::parse();
    opts.log.init_logger();

    info!("logging initialized!");
    info!("CLI opts: {:?}", &opts);

    match opts.cmd {
        cli::Command::Info(info) => info.display(),
        cli::Command::Exec(exec) => {
            let backend = exec.backend.pick()?;
            let binary = mmarinus::Kind::Private.load::<mmarinus::perms::Read, _>(&exec.binpath)?;
            #[cfg(not(feature = "gdb"))]
            let gdblisten = None;

            #[cfg(feature = "gdb")]
            let gdblisten = Some(exec.gdblisten);

            let exit_code = keep_exec(backend, backend.shim(), binary, gdblisten)?;
            std::process::exit(exit_code);
        }
        cli::Command::Run(run) => {
            let modfile = File::open(run.module)?;
            let open_fd = modfile.as_raw_fd();
            // FIXME (v0.1.0 KEEP-CONFIG HACK): since we don't have any way to
            // pass configuration or data into a keep yet, for v0.1.0 we've
            // just hardcoded exec-wasmtime to assume the module is open for reading
            // on FD3. That *should* always be the case here (since nothing
            // above opens files or anything), but if that assumption is wrong
            // then things will break mysteriously later on. So this assert
            // is just here to make them break earlier, and with less mystery.
            assert!(open_fd == 3, "module got unexpected fd {}", open_fd);

            let configfile = match run.workldr.wasmcfgfile.as_ref() {
                Some(name) => {
                    let file = File::open(name)?;
                    let fd = file.as_raw_fd();
                    assert!(fd == 4, "config got unexpected fd {}", fd);

                    Some(file)
                }
                None => None,
            };

            // TODO: pass open_fd (or its contents) into the keep.
            let backend = run.backend.pick()?;
            let workldr = run.workldr.pick()?;
            #[cfg(not(feature = "gdb"))]
            let gdblisten = None;

            #[cfg(feature = "gdb")]
            let gdblisten = Some(run.gdblisten);

            let exit_code = keep_exec(backend, backend.shim(), workldr.exec(), gdblisten)?;
            drop(configfile);
            drop(modfile);
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
