// SPDX-License-Identifier: Apache-2.0

use super::{BackendOptions, StructOpt, WorkldrOptions};

use std::{fmt::Debug, path::PathBuf};

/// Run a WebAssembly module inside an Enarx Keep.
#[derive(StructOpt, Debug)]
pub struct Options {
    #[structopt(flatten)]
    pub backend: BackendOptions,

    #[structopt(flatten)]
    pub workldr: WorkldrOptions,

    /// Path of the WebAssembly module to run
    #[structopt(value_name = "MODULE", parse(from_os_str))]
    pub module: PathBuf,

    /// gdb options
    #[cfg(feature = "gdb")]
    #[structopt(long, default_value = "localhost:23456")]
    pub gdblisten: String,
}
