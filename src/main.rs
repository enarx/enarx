// SPDX-License-Identifier: Apache-2.0

//! This crate provides the `enarx` executable which loads `static-pie`
//! binaries into an Enarx Keep - that is a hardware isolated environment using
//! technologies such as Intel SGX or AMD SEV.
//!
//! # Building
//!
//! Please see **BUILD.md** for instructions.
//!
//! # Run Tests
//!
//!     $ cargo test
//!
//! # Build and Run an Application
//!
//!     $ cat > test.c <<EOF
//!     #include <stdio.h>
//!
//!     int main() {
//!         printf("Hello World!\n");
//!         return 0;
//!     }
//!     EOF
//!
//!     $ musl-gcc -static-pie -fPIC -o test test.c
//!     $ target/debug/enarx exec ./test
//!     Hello World!
//!
//! # Select a Different Backend
//!
//! `enarx exec` will probe the machine it is running on
//! in an attempt to deduce an appropriate deployment backend unless
//! that target is already specified in an environment variable
//! called `ENARX_BACKEND`.
//!
//! To see what backends are supported on your system, run:
//!
//!     $ target/debug/enarx info
//!
//! To manually select a backend, set the `ENARX_BACKEND` environment
//! variable:
//!
//!     $ ENARX_BACKEND=sgx target/debug/enarx exec ./test
//!
//! Note that some backends are conditionally compiled. They can all
//! be compiled in like so:
//!
//!     $ cargo build --all-features
//!
//! Or specific backends can be compiled in:
//!
//!     $ cargo build --features=backend-sgx,backend-kvm

#![deny(clippy::all)]
#![deny(missing_docs)]
#![feature(asm)]

mod backend;
mod protobuf;
mod workldr;

use backend::{Backend, Command};
use workldr::Workldr;

use std::convert::TryInto;
use std::path::PathBuf;

use anyhow::Result;
use structopt::StructOpt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

/// Prints information about your current platform
#[derive(StructOpt)]
struct Info {}

/// Executes a keep
#[derive(StructOpt)]
struct Exec {
    /// The payload to run inside the keep
    code: Option<PathBuf>,
}

#[derive(StructOpt)]
#[structopt(version=VERSION, author=AUTHORS.split(";").nth(0).unwrap())]
enum Options {
    Info(Info),
    Exec(Exec),
}

#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<()> {
    let backends: &[Box<dyn Backend>] = &[
        #[cfg(feature = "backend-sgx")]
        Box::new(backend::sgx::Backend),
        #[cfg(feature = "backend-kvm")]
        Box::new(backend::kvm::Backend),
    ];

    let workldrs: &[Box<dyn Workldr>] = &[
        #[cfg(feature = "wasmldr")]
        Box::new(workldr::wasmldr::Wasmldr),
    ];

    match Options::from_args() {
        Options::Info(_) => info(backends),
        Options::Exec(e) => {
            // FUTURE: accept tenant-provided shim, or fall back to builtin..
            let backend = backend(backends);
            let shim_bytes = backend.shim();
            if let Some(path) = e.code {
                let map = mmarinus::Kind::Private.load::<mmarinus::perms::Read, _>(&path)?;
                exec(backend, shim_bytes, map)
            } else {
                exec(backend, shim_bytes, workldr(workldrs).exec())
            }
        }
    }
}

#[allow(clippy::unnecessary_wraps)]
fn info(backends: &[Box<dyn Backend>]) -> Result<()> {
    use colorful::*;

    for backend in backends {
        println!("Backend: {}", backend.name());

        let data = backend.data();

        for datum in &data {
            let icon = match datum.pass {
                true => "✔".green(),
                false => "✗".red(),
            };

            if let Some(info) = datum.info.as_ref() {
                println!(" {} {}: {}", icon, datum.name, info);
            } else {
                println!(" {} {}", icon, datum.name);
            }
        }

        for datum in &data {
            if let Some(mesg) = datum.mesg.as_ref() {
                println!("\n{}\n", mesg);
            }
        }
    }

    Ok(())
}

#[inline]
fn backend(backends: &[Box<dyn Backend>]) -> &dyn Backend {
    let keep = std::env::var_os("ENARX_BACKEND").map(|x| x.into_string().unwrap());

    let backend = backends
        .iter()
        .filter(|b| keep.is_none() || keep == Some(b.name().into()))
        .find(|b| b.have());

    match (keep, backend) {
        (Some(name), None) => panic!("Keep backend '{:?}' is unsupported.", name),
        (None, None) => panic!("No supported backend found!"),
        (_, Some(backend)) => &**backend,
    }
}

#[inline]
fn workldr(workldrs: &[Box<dyn Workldr>]) -> &dyn Workldr {
    // NOTE: this is stupid, but we only have one workldr, so... ¯\_(ツ)_/¯
    &*workldrs[0]
}

fn exec(backend: &dyn Backend, shim: impl AsRef<[u8]>, exec: impl AsRef<[u8]>) -> Result<()> {
    //let map = mmarinus::Kind::Private.load::<mmarinus::perms::Read, _>(&opts.code)?;

    let keep = backend.keep(shim.as_ref(), exec.as_ref())?;
    let mut thread = keep.clone().spawn()?.unwrap();
    loop {
        match thread.enter()? {
            Command::SysCall(block) => unsafe {
                block.msg.rep = block.msg.req.syscall();
            },

            Command::CpuId(block) => unsafe {
                let cpuid = core::arch::x86_64::__cpuid_count(
                    block.msg.req.arg[0].try_into().unwrap(),
                    block.msg.req.arg[1].try_into().unwrap(),
                );

                block.msg.req.arg[0] = cpuid.eax.into();
                block.msg.req.arg[1] = cpuid.ebx.into();
                block.msg.req.arg[2] = cpuid.ecx.into();
                block.msg.req.arg[3] = cpuid.edx.into();
            },

            Command::Continue => (),
        }
    }
}
