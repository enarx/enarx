// SPDX-License-Identifier: Apache-2.0

//! The Enarx Keep runtime binary.
//! It can be used to run a WASM workload, further referenced as the workload.
//!
//! ## Example invocation
//! In a Linux shell environment, a workload file can be redirected to filedescriptor 3,
//! which will subsequently be read by the WASM runtime execution.
//!
//! ```console
//! $ RUST_LOG=keep_runtime=info RUST_BACKTRACE=1 cargo run 3<../keep-libruntime/fixtures/return_1.wkld
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

use log::{debug, info};
use wasm_workload::{Result, Workload, WorkloadReader};

fn main() -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::default());

    #[cfg(target_os = "linux")]
    let workload_reader = wasm_workload::FdWorkloadReader::new(3).get_reader()?;

    let workload = Workload::deserialize_from_reader(workload_reader).unwrap();
    debug!("retrieved workload: {:?}", &workload);

    let result = workload.run(None, None, None)?;

    info!("got result: {:#?}", result);

    Ok(())
}
