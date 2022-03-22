// SPDX-License-Identifier: Apache-2.0

//! This crate provides the `enarx` executable, which is a tool for running
//! code inside an Enarx Keep - that is a hardware isolated environment using
//! technologies such as Intel SGX or AMD SEV.
//!
//! For more information about the project and the technology used
//! visit the [Enarx Project home page](https://enarx.dev/).
//!
//! # SGX and SEV machine setup
//!
//! Please see
//! [this wiki page](https://github.com/enarx/enarx/wiki/Reproducible-builds-and-Machine-setup)
//! for instructions.
//!
//! # Building and Testing Enarx
//!
//! Please see [BUILD.md](https://github.com/enarx/enarx/blob/main/BUILD.md) for instructions.
//!
//! # Installing Enarx
//!
//! Please see
//! [this wiki page](https://github.com/enarx/enarx/wiki/Install-Enarx)
//! for instructions.
//!
//! # Build and run a WebAssembly module
//!
//! Install the Webassembly rust toolchain:
//!
//! ```sh
//! $ rustup target install wasm32-wasi
//! ```
//!
//! Create simple rust program:
//!
//! ```sh
//! $ cargo init --bin hello-world
//! $ cd hello-world
//! $ echo 'fn main() { println!("Hello, Enarx!"); }' > src/main.rs
//! $ cargo build --release --target=wasm32-wasi
//! ```
//!
//! Assuming you did install the `enarx` binary and have it in your `$PATH`, you can
//! now run the Webassembly program in an Enarx keep.
//!
//! ```sh
//! $ enarx run target/wasm32-wasi/release/hello-world.wasm
//! […]
//! Hello, Enarx!
//! ```
//!
//! If you want to suppress the debug output, add `2>/dev/null`.
//!
//! # Select a Different Backend
//!
//! `enarx` will probe the machine it is running on in an attempt to deduce an
//! appropriate deployment backend. To see what backends are supported on your
//! system, run:
//!
//! ```sh
//! $ enarx info
//! ```
//!
//! You can manually select a backend with the `--backend` option, or by
//! setting the `ENARX_BACKEND` environment variable:
//!
//! ```sh
//! $ enarx run --backend=sgx target/wasm32-wasi/release/hello-world.wasm
//! $ ENARX_BACKEND=sgx enarx run target/wasm32-wasi/release/hello-world.wasm
//! ```

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
use log::info;
use structopt::StructOpt;

// This defines the toplevel `enarx` CLI
#[derive(StructOpt, Debug)]
#[structopt(
    setting = structopt::clap::AppSettings::DeriveDisplayOrder,
)]
struct Options {
    /// Logging options
    #[structopt(flatten)]
    log: cli::LogOptions,

    /// Subcommands (with their own options)
    #[structopt(flatten)]
    cmd: cli::Command,
}

fn main() -> Result<()> {
    let opts = Options::from_args();
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
            // just hardcoded wasmldr to assume the module is open for reading
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
