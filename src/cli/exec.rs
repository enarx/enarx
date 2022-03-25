// SPDX-License-Identifier: Apache-2.0

use crate::cli::BackendOptions;

use std::path::PathBuf;

use clap::Args;

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
#[derive(Args, Debug)]
pub struct Options {
    #[clap(flatten)]
    pub backend: BackendOptions,

    /// Binary to load and run inside the keep
    #[clap(value_name = "BINARY")]
    pub binpath: PathBuf,

    /// gdb options
    #[cfg(feature = "gdb")]
    #[clap(long, default_value = "localhost:23456")]
    pub gdblisten: String,
}
