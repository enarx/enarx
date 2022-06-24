// SPDX-License-Identifier: Apache-2.0

use clap::Args;

/// List the names of all outstanding access tokens for a repository.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        unimplemented!()
    }
}
