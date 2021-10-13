// SPDX-License-Identifier: Apache-2.0

use crate::cli::{BackendOptions, StructOpt};

use std::path::PathBuf;

/// Execute a static-PIE binary inside an Enarx Keep
#[derive(StructOpt, Debug)]
pub struct Options {
    #[structopt(flatten)]
    pub backend: BackendOptions,

    /// External static PIE binary to run inside the keep
    pub code: PathBuf,
}
