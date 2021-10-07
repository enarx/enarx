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
//! [INFO  wasmldr] opts: RunOptions {
//!         envs: [],
//!         module: Some(
//!             "return_1.wasm",
//!         ),
//!         args: [],
//!     }
//! [INFO  wasmldr] reading module from "return_1.wasm"
//! [INFO  wasmldr] running workload
//! [WARN  wasmldr::workload] 🌭DEV-ONLY BUILD🌭: inheriting stdio from calling process
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

mod cli;
mod workload;

use log::{debug, info};
use structopt::StructOpt;

use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;

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
        unsafe { File::from_raw_fd(3) }
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
