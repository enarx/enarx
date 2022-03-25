// SPDX-License-Identifier: Apache-2.0

use super::{BackendOptions, WorkldrOptions};

use std::{fmt::Debug, path::PathBuf};

use clap::Args;

/// Run a WebAssembly module inside an Enarx Keep.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(flatten)]
    pub backend: BackendOptions,

    #[clap(flatten)]
    pub workldr: WorkldrOptions,

    /// Path of the WebAssembly module to run
    #[clap(value_name = "MODULE", parse(from_os_str))]
    pub module: PathBuf,

    /// gdb options
    #[cfg(feature = "gdb")]
    #[clap(long, default_value = "localhost:23456")]
    pub gdblisten: String,
}
