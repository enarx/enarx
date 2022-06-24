// SPDX-License-Identifier: Apache-2.0

use clap::Args;

/// Yank all packages published to a repository.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        unimplemented!()
    }
}
