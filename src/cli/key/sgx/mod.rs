// SPDX-License-Identifier: Apache-2.0

mod create;

use clap::Subcommand;

/// SGX-specific functionality
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Create(create::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Create(cmd) => cmd.execute(),
        }
    }
}
