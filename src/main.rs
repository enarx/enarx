// SPDX-License-Identifier: Apache-2.0

//! This crate provides the `enarx-keepldr` executable which loads `static-pie`
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
//!     $ target/debug/enarx-keepldr exec ./test
//!     Hello World!
//!
//! # Select a Different Backend
//!
//! `enarx-keepldr exec` will probe the machine it is running on
//! in an attempt to deduce an appropriate deployment backend unless
//! that target is already specified in an environment variable
//! called `ENARX_BACKEND`.
//!
//! To see what backends are supported on your system, run:
//!
//!     $ target/debug/enarx-keepldr info
//!
//! To manually select a backend, set the `ENARX_BACKEND` environment
//! variable:
//!
//!     $ ENARX_BACKEND=sgx target/debug/enarx-keepldr exec ./test
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
mod binary;
mod protobuf;

// workaround for sallyport tests, until we have internal crates
pub use sallyport::Request;

use backend::{Backend, Command};
use binary::{Component, ComponentType};

use anyhow::Result;
use structopt::StructOpt;

use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

/// Prints information about your current platform
#[derive(StructOpt)]
struct Info {}

/// Executes a keep
#[derive(StructOpt)]
struct Exec {
    /// The socket to use for preattestation
    #[structopt(short, long)]
    sock: Option<PathBuf>,

    /// The payload to run inside the keep
    code: PathBuf,
}

/// Get a report from a keep
#[derive(StructOpt)]
struct Report {
    /// The payload to run inside the keep
    code: PathBuf,
}

#[derive(StructOpt)]
#[structopt(version=VERSION, author=AUTHORS.split(";").nth(0).unwrap())]
enum Options {
    Info(Info),
    Exec(Exec),
    Report(Report),
}

#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<()> {
    let backends: &[Box<dyn Backend>] = &[
        #[cfg(feature = "backend-sev")]
        Box::new(backend::sev::Backend),
        #[cfg(feature = "backend-sgx")]
        Box::new(backend::sgx::Backend),
        #[cfg(feature = "backend-kvm")]
        Box::new(backend::kvm::Backend),
    ];

    match Options::from_args() {
        Options::Info(_) => info(backends),
        Options::Exec(e) => exec(backends, e),
        Options::Report(e) => measure(backends, e),
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

fn measure(backends: &[Box<dyn Backend>], opts: Report) -> Result<()> {
    let backend = backend(backends);

    let map = mmarinus::Kind::Private.load::<mmarinus::perms::Read, _>(&opts.code)?;
    let shim = Component::from_bytes(backend.shim(), ComponentType::Shim)?;
    let code = Component::from_bytes(&map, ComponentType::Payload)?;
    let json = backend.measure(shim, code)?;
    println!("{}", json);

    Ok(())
}

fn exec(backends: &[Box<dyn Backend>], opts: Exec) -> Result<()> {
    let backend = backend(backends);

    let map = mmarinus::Kind::Private.load::<mmarinus::perms::Read, _>(&opts.code)?;
    let shim = Component::from_bytes(backend.shim(), ComponentType::Shim)?;
    let code = Component::from_bytes(&map, ComponentType::Payload)?;
    let keep = backend.build(shim, code, opts.sock.as_deref())?;

    let mut thread = keep.clone().spawn()?.unwrap();
    loop {
        match thread.enter()? {
            Command::SysCall(block) => unsafe {
                block.msg.rep = block.msg.req.syscall();
            },
            Command::Continue => (),
        }
    }
}
