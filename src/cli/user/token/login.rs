// SPDX-License-Identifier: Apache-2.0

use clap::Args;

/// Log in to an Enarx package host and save credentials locally.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        unimplemented!()
    }
}
