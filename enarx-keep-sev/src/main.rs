// SPDX-License-Identifier: Apache-2.0

//! `enarx-keep-sev` is the Enarx Keep abstraction over AMD's Secure
//! Encrypted Virtualization (SEV) technology.

#![deny(clippy::all)]
#![deny(missing_docs)]

use structopt::StructOpt;

use std::error::Error;
use std::fs::File;
use std::path::PathBuf;

#[derive(StructOpt, Debug)]
struct Args {
    /// The path to the kernel image/binary
    #[structopt(short, long, parse(from_os_str))]
    shim: PathBuf,

    /// The path to the application image/binary
    #[structopt(short, long, parse(from_os_str))]
    code: PathBuf,
}

fn main() {
    let args = Args::from_args();

    if let Err(err) = run(args) {
        let name = std::env::current_exe().expect("Couldn't get executable name");
        eprintln!("{} has encountered an error:", name.display());
        eprintln!("{:?}", err);
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let _kernel = File::open(args.shim)?;
    let _code = File::open(args.code)?;

    // TODO: KVM context creation

    // TODO: shim/code loading

    // TODO: Run the KVM VM + have event loop for servicing requests from the shim

    Ok(())
}
