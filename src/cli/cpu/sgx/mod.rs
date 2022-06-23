// SPDX-License-Identifier: Apache-2.0

mod register;

use clap::Subcommand;

/// SGX-specific functionality
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Register(register::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute(),
        }
    }
}
