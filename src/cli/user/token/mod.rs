// SPDX-License-Identifier: Apache-2.0

mod info;
mod login;
mod logout;

use clap::Subcommand;

/// Commands for working with local user tokens.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Info(info::Options),
    Login(login::Options),
    Logout(logout::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            Self::Login(cmd) => cmd.execute(),
            Self::Logout(cmd) => cmd.execute(),
        }
    }
}
