// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use clap::Args;

/// Log out of an Enarx package host and delete local credentials.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        unimplemented!()
    }
}
