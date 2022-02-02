// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs, unused_variables)] // This is a work-in-progress, so...

use structopt::StructOpt;

use std::path::PathBuf;

// The main StructOpt for running `wasmldr` directly
#[derive(StructOpt, Debug)]
pub struct RunOptions {
    /// Path of the WebAssembly module to run
    #[structopt(index = 1, value_name = "MODULE", parse(from_os_str))]
    pub module: Option<PathBuf>,

    #[structopt(long, value_name = "CONFIG", parse(from_os_str))]
    pub config: Option<PathBuf>,
}
