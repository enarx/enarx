// SPDX-License-Identifier: Apache-2.0

//! `wasmldr` - the Enarx WebAssembly loader
//!
//! `wasmldr` is responsible for loading and running WebAssembly modules
//! inside an Enarx keep.
//!
//! Users generally won't execute `wasmldr` directly, but for test/debugging
//! purposes it can be used to run a .wasm file with given command-line
//! arguments and environment variables.
//!
//! ## Example invocation
//!
//! ```console
//! $ wat2wasm ../tests/wasm/return_1.wat
//! $ RUST_LOG=wasmldr=info RUST_BACKTRACE=1 cargo run -- return_1.wasm
//!     Finished dev [unoptimized + debuginfo] target(s) in 0.03s
//!      Running `target/x86_64-unknown-linux-musl/debug/wasmldr return_1.wasm`
//! [INFO  wasmldr] version 0.2.0 starting up
//! [WARN  wasmldr] 🌭DEV-ONLY BUILD, NOT FOR PRODUCTION USE🌭
//! [INFO  wasmldr] opts: RunOptions {
//!         envs: [],
//!         module: Some(
//!             "return_1.wasm",
//!         ),
//!         args: [],
//!     }
//! [INFO  wasmldr] reading module from "return_1.wasm"
//! [INFO  wasmldr] running workload
//! [WARN  wasmldr::workload] inheriting stdio from calling process
//! [INFO  wasmldr] got result: Ok(
//!         [
//!             I32(
//!                 1,
//!             ),
//!         ],
//!     )
//! ```
//!
//! If no filename is given, `wasmldr` expects to read the WebAssembly module
//! from file descriptor 3, so this would be equivalent:
//! ```console
//! $ RUST_LOG=wasmldr=info RUST_BACKTRACE=1 cargo run -- 3< return_1.wasm
//!  ```
//!
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(rust_2018_idioms)]

mod cli;
mod config;
mod workload;

use log::{debug, info, warn};
use structopt::StructOpt;

use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;

// v0.1.0 KEEP-CONFIG HACK
// We don't yet have a well-defined way to pass runtime configuration from
// the frontend/CLI into the keep, so the keep configuration is pre-defined:
//   * the .wasm module is open on fd3 and gets no arguments or env vars
//   * stdin, stdout, and stderr are enabled and should go to fd 0,1,2
//   * logging should be turned on at "debug" level, output goes to stderr
//

fn main() {
    // KEEP-CONFIG HACK: we've inherited stdio and the shim sets
    // "RUST_LOG=debug", so this should make logging go to stderr.
    // FUTURE: we should have a keep-provided debug channel where we can
    // (safely, securely) send logs. Might need our own logger for that..
    env_logger::Builder::from_default_env().init();

    warn!("🌭DEV-ONLY BUILD, NOT FOR PRODUCTION USE🌭");

    debug!("parsing argv");
    let opts = cli::RunOptions::from_args();
    info!("opts: {:#?}", opts);

    let mut reader = if let Some(module) = opts.module {
        info!("reading module from {:?}", &module);
        File::open(&module).expect("Unable to open file")
    } else {
        // v0.1.0 KEEP-CONFIG HACK: just assume module is on FD3
        info!("reading module from fd 3");
        unsafe { File::from_raw_fd(3) }
    };

    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .expect("Failed to load workload");

    let mut cnf_reader = if let Some(cnf_path) = opts.config {
        info!("reading config from {:?}", &cnf_path);
        File::open(&cnf_path).expect("Unable to open file")
    } else {
        // v0.1.0 KEEP-CONFIG HACK: just assume config is on FD4
        info!("reading config from fd 4");
        unsafe { File::from_raw_fd(4) }
    };

    let mut buf = String::new();
    let config: config::Config = cnf_reader
        .read_to_string(&mut buf)
        .map(|_| toml::from_str(&buf).unwrap_or_else(|_| panic!("Invalid config file {}", buf)))
        .unwrap_or_else(|_| config::Config::default());

    // TODO: split up / refactor workload::run() so we can configure things
    // like WASI stdio or wasmtime features before executing the workload..

    info!("running workload");
    let result = workload::run(bytes, &config);
    info!("got result: {:#?}", result);

    // FUTURE: produce attestation report here
    // TODO: print the returned value(s) in some format (json?)

    // Choose an appropriate exit code from our result
    std::process::exit(match result {
        Ok(_) => 0,
        Err(e) => i32::from(e),
    });
}
