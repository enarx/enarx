// SPDX-License-Identifier: Apache-2.0

mod create;
mod digest;
pub mod sign;

use std::process::ExitCode;

use clap::Subcommand;

/// SEV-specific functionality
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Digest(digest::Options),
    Sign(sign::Options),
    Create(create::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Digest(cmd) => cmd.execute(),
            Self::Sign(cmd) => cmd.execute(),
            Self::Create(cmd) => cmd.execute(),
        }
    }
}
