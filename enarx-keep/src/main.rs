// SPDX-License-Identifier: Apache-2.0

//! Loads keeps from their backends.

#![deny(clippy::all)]
#![deny(missing_docs)]

mod backend;
mod binary;

use backend::{Backend, Command};
use binary::Component;

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
    /// The specific keep backend to use
    #[structopt(short, long)]
    keep: Option<String>,

    /// The socket to use for preattestation
    #[structopt(short, long)]
    sock: Option<PathBuf>,

    /// The payload to run inside the keep
    code: PathBuf,
}

#[derive(StructOpt)]
#[structopt(version=VERSION, author=AUTHORS.split(";").nth(0).unwrap())]
enum Options {
    Info(Info),
    Exec(Exec),
}

fn main() -> Result<()> {
    let backends: &[Box<dyn Backend>] = &[
        Box::new(backend::sev::Backend),
        Box::new(backend::sgx::Backend),
        Box::new(backend::kvm::Backend),
    ];

    match Options::from_args() {
        Options::Info(_) => info(backends),
        Options::Exec(e) => exec(backends, e),
    }
}

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

#[allow(unreachable_code)]
fn exec(backends: &[Box<dyn Backend>], opts: Exec) -> Result<()> {
    let code = Component::from_path(&opts.code)?;

    let backend = backends
        .iter()
        .filter(|b| opts.keep.is_none() || opts.keep == Some(b.name().into()))
        .find(|b| b.have())
        .expect("No supported backend found!");

    let keep = backend.build(code, opts.sock.as_deref())?;

    let mut thread = keep.clone().add_thread()?;
    loop {
        match thread.enter()? {
            Command::SysCall(block) => unsafe {
                block.msg.rep = block.msg.req.syscall();
            },
        }
    }

    unreachable!();
}
