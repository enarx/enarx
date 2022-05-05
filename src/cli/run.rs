// SPDX-License-Identifier: Apache-2.0

use super::BackendOptions;

use std::fmt::Debug;

use clap::Args;
use url::Url;

/// Run an Enarx package inside an Enarx Keep.
#[derive(Args, Debug)]
pub struct Options {
    #[clap(flatten)]
    pub backend: BackendOptions,

    /// URL of the package to run.
    #[clap(value_name = "PACKAGE")]
    pub package: Url,

    /// URL of the steward to use.
    #[clap(long)]
    pub steward: Option<Url>,

    /// gdb options
    #[cfg(feature = "gdb")]
    #[clap(long, default_value = "localhost:23456")]
    pub gdblisten: String,
}
