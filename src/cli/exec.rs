// SPDX-License-Identifier: Apache-2.0

use crate::cli::{BackendOptions, StructOpt};

use std::path::PathBuf;

/// Execute a (static, PIE) binary inside an Enarx Keep.
///
/// The binary must be a statically linked position-independent executable,
/// compiled with flags like `-nostdlib -static-pie -fPIC`. No commandline
/// arguments are passed, the program's `argv[0]` will be `/init`, and the
/// environment is empty except for `LANG=C`.
///
/// This subcommand is hidden from the main help because it's unlikely to be
/// useful because of the restrictions above. It's mainly used for
/// development and integration tests.
#[derive(StructOpt, Debug)]
pub struct Options {
    #[structopt(flatten)]
    pub backend: BackendOptions,

    /// Binary to load and run inside the keep
    #[structopt(value_name = "BINARY")]
    pub binpath: PathBuf,

    /// gdb options
    #[cfg(feature = "gdb")]
    #[structopt(long, default_value = "localhost:23456")]
    pub gdblisten: String,
}
