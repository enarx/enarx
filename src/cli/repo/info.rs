// SPDX-License-Identifier: Apache-2.0

use clap::Args;

/// List all tags associated with a repository.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        unimplemented!()
    }
}
