// SPDX-License-Identifier: Apache-2.0

mod register;

use std::process::ExitCode;

use clap::Subcommand;

/// SGX-specific functionality
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Register(register::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Register(cmd) => cmd.execute(),
        }
    }
}
