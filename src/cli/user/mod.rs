// SPDX-License-Identifier: Apache-2.0

mod info;
mod token;

use clap::Subcommand;

/// Commands for working with user accounts on an Enarx package host.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Info(info::Options),
    #[clap(subcommand)]
    Token(token::Subcommands),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            Self::Token(subcmd) => subcmd.dispatch(),
        }
    }
}
