// SPDX-License-Identifier: Apache-2.0

mod info;
mod register;
mod search;
mod token;
mod yank;

use clap::Subcommand;

/// Commands for working with repositories on an Enarx package host.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Info(info::Options),
    Register(register::Options),
    #[clap(hide = true)]
    Search(search::Options),
    #[clap(hide = true)]
    Yank(yank::Options),
    #[clap(subcommand, hide = true)]
    Token(token::Subcommands),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            Self::Register(cmd) => cmd.execute(),
            Self::Search(cmd) => cmd.execute(),
            Self::Yank(cmd) => cmd.execute(),
            Self::Token(subcmd) => subcmd.dispatch(),
        }
    }
}
