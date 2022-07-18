// SPDX-License-Identifier: Apache-2.0

mod update;
mod vcek;

use clap::Subcommand;

/// SNP-specific functionality
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Vcek(vcek::Options),
    Update(update::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Vcek(cmd) => cmd.execute(),
            Self::Update(cmd) => cmd.execute(),
        }
    }
}
