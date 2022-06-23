// SPDX-License-Identifier: Apache-2.0

mod info;
mod update;

use clap::Subcommand;

/// SNP-specific functionality
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Info(info::Options),
    Update(update::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            Self::Update(cmd) => cmd.execute(),
        }
    }
}
