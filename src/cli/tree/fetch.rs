// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use clap::Args;

/// Download a file tree from an Enarx package host.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        unimplemented!()
    }
}
