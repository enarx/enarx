// SPDX-License-Identifier: Apache-2.0

pub(crate) mod crl;
pub(crate) mod update;
mod vcek;

use std::process::ExitCode;

use clap::Subcommand;

/// SNP-specific functionality
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    CacheCRL(crl::CrlCache),
    Vcek(vcek::Options),
    Update(update::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::CacheCRL(cmd) => cmd.execute(),
            Self::Vcek(cmd) => cmd.execute(),
            Self::Update(cmd) => cmd.execute(),
        }
    }
}
