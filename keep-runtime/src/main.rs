// SPDX-License-Identifier: Apache-2.0

//! The Enarx Keep runtime binary.
//!
//! It can be used to run a Wasm file with given command-line
//! arguments and environment variables.
//!
//! ## Example invocation
//!
//! ```console
//! $ RUST_LOG=keep_runtime=info RUST_BACKTRACE=1 cargo run fixtures/return_1.wasm
//!    Compiling keep-runtime v0.1.0 (/home/steveej/src/job-redhat/enarx/github_enarx_enarx/keep-runtime)
//!     Finished dev [unoptimized + debuginfo] target(s) in 4.36s
//!      Running `target/debug/keep-runtime`
//! [2020-01-23T21:58:16Z INFO  keep_runtime] got result: [
//!         I32(
//!             1,
//!         ),
//!     ]
//! ```
#![deny(missing_docs)]
#![deny(clippy::all)]

mod workload;

use log::info;

fn main() {
    let _ = env_logger::try_init_from_env(env_logger::Env::default());

    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap();
    let vars = std::env::vars();

    let bytes = std::fs::read(&path).expect("Unable to open file");

    let result = workload::run(&bytes, args, vars).expect("Failed to run workload");

    info!("got result: {:#?}", result);
}
