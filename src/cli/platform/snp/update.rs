// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::snp::vcek::vcek_write;

use clap::Args;

/// Download the VCEK certificate for this platform.
///
/// The certificate will be saved to a cache file in `/var/cache/amd-sev/`
#[derive(Args, Debug)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        // try to write to the system cache
        vcek_write()?;
        Ok(())
    }
}
