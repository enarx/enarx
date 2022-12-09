// SPDX-License-Identifier: Apache-2.0

mod exec;

use std::process::ExitCode;

use clap::Subcommand;

/// Deliberately unstable commands.
///
/// All commands listed here are officially unsupported and
/// subject to change without warning at any time.
/// Use these commands at your own risk.
#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Exec(exec::Options),
}

impl Subcommands {
    pub fn dispatch(self) -> anyhow::Result<ExitCode> {
        match self {
            #[cfg(not(enarx_with_shim))]
            Self::Exec(_) => anyhow::bail!("exec option not supported"),
            #[cfg(enarx_with_shim)]
            Self::Exec(cmd) => cmd.execute(),
        }
    }
}
