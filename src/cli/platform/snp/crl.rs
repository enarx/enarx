// SPDX-License-Identifier: Apache-2.0

use super::super::caching::save_file;
use crate::backend::sev::snp::vcek::sev_cache_dir;

use std::process::ExitCode;

use clap::Args;

const GENOA: &str = "https://kdsintf.amd.com/vcek/v1/Genoa/crl";
const MILAN: &str = "https://kdsintf.amd.com/vcek/v1/Milan/crl";

/// Fetch AMD's Certificate Revocation Lists (CRLs),
/// saving as cached files in `/var/cache/amd-sev/` directory
#[derive(Args, Debug)]
pub struct CrlCache {}

impl CrlCache {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        let dir = sev_cache_dir()?;
        save_file(GENOA, &dir)?;
        save_file(MILAN, &dir)?;
        Ok(ExitCode::SUCCESS)
    }
}
