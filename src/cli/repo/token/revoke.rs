// SPDX-License-Identifier: Apache-2.0

use clap::Args;

/// Revoke a repository access token.
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        unimplemented!()
    }
}
