// SPDX-License-Identifier: Apache-2.0

mod create;
mod digest;

use std::process::ExitCode;

use clap::Subcommand;

/// SGX-specific functionality
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Create(create::Options),
    Digest(digest::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Create(cmd) => cmd.execute(),
            Self::Digest(cmd) => cmd.execute(),
        }
    }
}
