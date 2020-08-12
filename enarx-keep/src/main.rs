// SPDX-License-Identifier: Apache-2.0

//! Loads keeps from their backends.

#![deny(clippy::all)]
#![deny(missing_docs)]

mod backend;
mod binary;

use std::collections::HashMap;
use std::io::Result;
use structopt::StructOpt;

use backend::{Backend, Command};
use binary::Component;
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

    #[structopt(short, long, parse(from_os_str))]
    shim: Option<PathBuf>,

    // FIXME: https://github.com/enarx/enarx/issues/831
    #[structopt(short = "l", long = "shim-log-level", default_value = "0")]
    shim_log_level: u8,

    /// The payload to run inside the keep
    code: String,
}

#[derive(StructOpt)]
#[structopt(version=VERSION, author=AUTHORS.split(";").nth(0).unwrap())]
enum Options {
    Info(Info),
    Exec(Exec),
}

fn main() -> Result<()> {
    let mut backends = HashMap::<String, Box<dyn Backend>>::new();

    backends.insert("kvm".into(), Box::new(backend::kvm::Backend));
    backends.insert("sev".into(), Box::new(backend::sev::Backend));
    backends.insert("sgx".into(), Box::new(backend::sgx::Backend));

    match Options::from_args() {
        Options::Info(_) => info(backends),
        Options::Exec(e) => exec(backends, e),
    }
}

fn info(backends: HashMap<String, Box<dyn Backend>>) -> Result<()> {
    use colorful::*;

    for (name, backend) in &backends {
        println!("Backend: {}", name);

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
fn exec(backends: HashMap<String, Box<dyn Backend>>, opts: Exec) -> Result<()> {
    let code = Component::from_path(&opts.code)?;

    let backend = backends
        .into_iter()
        .filter(|(name, _)| opts.keep.is_none() || opts.keep.as_ref() == Some(name))
        .filter(|(_, backend)| backend.have())
        .map(|(_, backend)| backend)
        .next()
        .expect("No supported backend found!");

    let shim = Component::from_path(opts.shim.unwrap_or(backend.shim()?))?;

    let keep = backend.build(shim, code, opts.shim_log_level)?;

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
