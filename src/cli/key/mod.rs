// SPDX-License-Identifier: Apache-2.0
//
pub mod sev;
mod sgx;

use clap::Subcommand;

/// Commands for utilizing keys to interact with Enarx.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    #[clap(subcommand)]
    Sgx(sgx::Subcommands),

    #[clap(subcommand)]
    Sev(sev::Subcommands),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Sgx(subcmd) => subcmd.dispatch(),
            Self::Sev(subcmd) => subcmd.dispatch(),
        }
    }
}
