// SPDX-License-Identifier: Apache-2.0

mod info;
mod login;
mod logout;
mod register;

use clap::Subcommand;

/// Commands for working with users on an Enarx package host.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    #[clap(hide = true)]
    Info(info::Options),
    Login(login::Options),
    #[clap(hide = true)]
    Logout(logout::Options),
    Register(register::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            Self::Login(cmd) => cmd.execute(),
            Self::Logout(cmd) => cmd.execute(),
            Self::Register(cmd) => cmd.execute(),
        }
    }
}
