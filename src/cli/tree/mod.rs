// SPDX-License-Identifier: Apache-2.0

mod digest;
mod fetch;
mod info;

use clap::Subcommand;

/// Commands for working with file trees inside of Enarx packages.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Info(info::Options),
    Fetch(fetch::Options),
    Digest(digest::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            Self::Fetch(cmd) => cmd.execute(),
            Self::Digest(cmd) => cmd.execute(),
        }
    }
}
