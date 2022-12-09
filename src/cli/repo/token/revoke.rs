// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use clap::Args;

/// Revoke a repository access token.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        unimplemented!()
    }
}
