// SPDX-License-Identifier: Apache-2.0

use clap::Args;

/// Yank a published package.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        unimplemented!()
    }
}
