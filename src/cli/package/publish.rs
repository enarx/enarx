// SPDX-License-Identifier: Apache-2.0

use clap::Args;

/// Publish a new package.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        unimplemented!()
    }
}
