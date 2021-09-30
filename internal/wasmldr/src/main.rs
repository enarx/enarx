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

fn main() {
    // Initialize the logger, taking settings from the default env vars
    env_logger::Builder::from_default_env().init();

    info!("version {} starting up", env!("CARGO_PKG_VERSION"));

    debug!("parsing argv");
    let opts = cli::RunOptions::from_args();
    info!("opts: {:#?}", opts);

    info!("reading {:?}", opts.module);
    // TODO: don't just panic here...
    let mut reader = File::open(&opts.module).expect("Unable to open file");

    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .expect("Failed to load workload");

    // FUTURE: measure opts.envs, opts.args, opts.wasm_features
    // FUTURE: fork() the workload off into a separate memory space

    info!("running workload");
    // TODO: pass opts.wasm_features
    let result = workload::run(bytes, opts.args, opts.envs).expect("Failed to run workload");
    info!("got result: {:#?}", result);
    // TODO: exit with the resulting code, if the result is a return code
    // FUTURE: produce attestation report here
}
