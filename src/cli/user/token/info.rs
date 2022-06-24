// SPDX-License-Identifier: Apache-2.0

use clap::Args;

/// List which users are logged in locally.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        unimplemented!()
    }
}
