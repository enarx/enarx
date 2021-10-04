// SPDX-License-Identifier: Apache-2.0

//! The Enarx Keep runtime binary.
//!
//! It can be used to run a Wasm file with given command-line
//! arguments and environment variables.
//!
//! ## Example invocation
//!
//! ```console
//! $ wat2wasm fixtures/return_1.wat
//! $ RUST_LOG=enarx_wasmldr=info RUST_BACKTRACE=1 cargo run return_1.wasm
//!     Finished dev [unoptimized + debuginfo] target(s) in 0.07s
//!      Running `target/x86_64-unknown-linux-musl/debug/enarx-wasmldr target/x86_64-unknown-linux-musl/debug/build/enarx-wasmldr-c374d181f6abdda0/out/fixtures/return_1.wasm`
//! [2020-09-10T17:56:18Z INFO  enarx_wasmldr] got result: [
//!         I32(
//!             1,
//!         ),
//!     ]
//! ```
//!
//! On Unix platforms, the command can also read the workload from the
//! file descriptor (3):
//! ```console
//! $ RUST_LOG=enarx_wasmldr=info RUST_BACKTRACE=1 cargo run 3< return_1.wasm
//! ```
//!
#![deny(missing_docs)]
#![deny(clippy::all)]

mod cli;
mod workload;

use log::{debug, info};
use structopt::StructOpt;

use std::fs::File;
use std::io::Read;
use std::os::unix::io::{FromRawFd, RawFd};

fn main() {
    // Initialize the logger, taking settings from the default env vars
    env_logger::Builder::from_default_env().init();

    info!("version {} starting up", env!("CARGO_PKG_VERSION"));

    debug!("parsing argv");
    let opts = cli::RunOptions::from_args();
    info!("opts: {:#?}", opts);

    let mut reader = if let Some(module) = opts.module {
        info!("reading module from {:?}", &module);
        File::open(&module).expect("Unable to open file")
    } else {
        info!("reading module from fd 3");
        unsafe { File::from_raw_fd(RawFd::from(3)) }
    };

    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .expect("Failed to load workload");

    // FUTURE: measure opts.envs, opts.args, opts.wasm_features
    // FUTURE: fork() the workload off into a separate memory space

    info!("running workload");
    // TODO: pass opts.wasm_features
    let result = workload::run(bytes, opts.args, opts.envs);
    info!("got result: {:#?}", result);

    // FUTURE: produce attestation report here
    // TODO: print the returned value(s) in some format (json?)

    // Choose an appropriate exit code
    // TODO: exit with the resulting code, if the result is a return code
    std::process::exit(match result {
        // Success -> EX_OK
        Ok(_) => 0,

        // wasmtime/WASI/module setup errors -> EX_DATAERR
        Err(workload::Error::ConfigurationError) => 65,
        Err(workload::Error::StringTableError) => 65,
        Err(workload::Error::InstantiationFailed) => 65,
        Err(workload::Error::ExportNotFound) => 65,
        Err(workload::Error::CallFailed) => 65,

        // Internal WASI errors -> EX_SOFTWARE
        Err(workload::Error::WASIError(_)) => 70,

        // General IO errors -> EX_IOERR
        Err(workload::Error::IoError(_)) => 74,
    });
}
