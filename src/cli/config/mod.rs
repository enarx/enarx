// SPDX-License-Identifier: Apache-2.0

mod init;

use clap::Subcommand;

/// Commands for working with Enarx configuration files.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Init(init::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Init(cmd) => cmd.execute(),
        }
    }
}
