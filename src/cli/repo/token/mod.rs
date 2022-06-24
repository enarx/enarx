// SPDX-License-Identifier: Apache-2.0

mod generate;
mod info;
mod revoke;

use clap::Subcommand;

/// Commands for working with repository access tokens.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Info(info::Options),
    Generate(generate::Options),
    Revoke(revoke::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            Self::Generate(cmd) => cmd.execute(),
            Self::Revoke(cmd) => cmd.execute(),
        }
    }
}
