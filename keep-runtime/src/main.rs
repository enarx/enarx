// SPDX-License-Identifier: Apache-2.0

//! The Enarx Keep runtime binary.
//!
//! It can be used to run a Wasm file with given command-line
//! arguments and environment variables.
//!
//! ## Example build and invocation
//!
//! ```console
//! $ RUST_LOG=keep_runtime=info RUST_BACKTRACE=1 cargo run fixtures/return_1.wat
//!    Compiling keep-runtime v0.1.0 (/home/steveej/src/job-redhat/enarx/github_enarx_enarx/keep-runtime)
//!     Finished dev [unoptimized + debuginfo] target(s) in 4.36s
//!      Running `target/debug/keep-runtime`
//! [2020-01-23T21:58:16Z INFO  keep_runtime] got result: [
//!         I32(
//!             1,
//!         ),
//!     ]
//! ```
//! ## Example build and invocation with binary
//!
//! ```console
//! $ cargo build --release
//! Finished release [optimized] target(s) in 0.06s
//! $ RUST_LOG=keep_runtime=info RUST_BACKTRACE=1 ./target/x86_64-unknown-linux-musl/release/
//!    keep-runtime fixtures/wasi_snapshot1.wat
//! [2020-05-31T10:30:34Z INFO  keep_runtime] got result: [
//!        I32(
//!            0,
//!        ),
//!    ]
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
