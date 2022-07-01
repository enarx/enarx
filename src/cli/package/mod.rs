// SPDX-License-Identifier: Apache-2.0

mod fetch;
mod info;
mod publish;
mod yank;

use clap::Subcommand;

/// Commands for working with Enarx packages.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Info(info::Options),
    #[clap(hide = true)]
    Fetch(fetch::Options),
    Publish(publish::Options),
    #[clap(hide = true)]
    Yank(yank::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            Self::Fetch(cmd) => cmd.execute(),
            Self::Publish(cmd) => cmd.execute(),
            Self::Yank(cmd) => cmd.execute(),
        }
    }
}
