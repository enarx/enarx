// SPDX-License-Identifier: Apache-2.0
//
#[cfg(enarx_with_shim)]
mod sev;
#[cfg(enarx_with_shim)]
mod sgx;

use clap::Subcommand;

/// Commands for utilizing keys to interact with Enarx.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    #[cfg(enarx_with_shim)]
    #[clap(subcommand)]
    Sgx(sgx::Subcommands),

    #[cfg(enarx_with_shim)]
    #[clap(subcommand)]
    Sev(sev::Subcommands),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<()> {
        match self {
            #[cfg(enarx_with_shim)]
            Self::Sgx(subcmd) => subcmd.dispatch(),
            #[cfg(enarx_with_shim)]
            Self::Sev(subcmd) => subcmd.dispatch(),
        }
    }
}
