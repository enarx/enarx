// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::snp::vcek::vcek_write;

use std::process::ExitCode;

use clap::Args;

/// Download the current VCEK certificate for this platform
/// to a cache file in the `/var/cache/amd-sev/` directory
#[derive(Args, Debug, Default)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        // try to write to the system cache
        vcek_write().map(|()| ExitCode::SUCCESS)
    }
}
