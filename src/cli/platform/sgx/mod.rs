// SPDX-License-Identifier: Apache-2.0

pub(crate) mod crl;
pub(crate) mod register;
pub(crate) mod tcb;

use std::process::ExitCode;

use clap::Subcommand;

/// SGX-specific functionality
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Register(register::Options),
    CacheCRL(crl::CrlCache),
    CachePCK(tcb::PckCache),
    CacheTCB(tcb::TcbCache),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Register(cmd) => cmd.execute(),
            Self::CacheCRL(cmd) => cmd.execute(),
            Self::CachePCK(cmd) => cmd.execute(),
            Self::CacheTCB(cmd) => cmd.execute(),
        }
    }
}
