// SPDX-License-Identifier: Apache-2.0

mod info;
#[cfg(enarx_with_shim)]
mod sgx;
#[cfg(enarx_with_shim)]
mod snp;

use clap::Subcommand;

/// Commands for configuration of trusted execution environments.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Info(info::Options),
    #[cfg(enarx_with_shim)]
    #[clap(subcommand)]
    Sgx(sgx::Subcommands),
    #[cfg(enarx_with_shim)]
    #[clap(subcommand)]
    Snp(snp::Subcommands),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute(),
            #[cfg(enarx_with_shim)]
            Self::Sgx(subcmd) => subcmd.dispatch(),
            #[cfg(enarx_with_shim)]
            Self::Snp(subcmd) => subcmd.dispatch(),
        }
    }
}
