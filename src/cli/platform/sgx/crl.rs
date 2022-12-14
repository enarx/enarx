// SPDX-License-Identifier: Apache-2.0

use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::process::ExitCode;

use super::super::caching::save_file;

use anyhow::Context;
use clap::Args;

const CERT_CRL: &str = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";
const PROCESSOR_CRL: &str =
    "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der";
const PLATFORM_CRL: &str =
    "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der";

/// Fetch Intel's Certificate Revocation Lists (CRLs),
/// saving as cached files in `/var/cache/intel-sgx/` directory
#[derive(Args, Debug)]
pub struct CrlCache {}

impl CrlCache {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        let dir = sgx_cache_dir()?;
        save_file(CERT_CRL, &dir)?;
        save_file(PROCESSOR_CRL, &dir)?;
        save_file(PLATFORM_CRL, &dir)?;
        Ok(ExitCode::SUCCESS)
    }
}

/// Returns the "system-level" search path for the SGX
/// CRLs (`/var/cache/intel-sgx`).
pub fn sgx_cache_dir() -> anyhow::Result<PathBuf> {
    const CACHE_DIR: &str = "/var/cache";

    let mut sys = PathBuf::from(CACHE_DIR);
    if sys.exists() && sys.is_dir() {
        sys.push("intel-sgx");
        Ok(sys)
    } else {
        Err(io::Error::from(ErrorKind::NotFound))
            .with_context(|| format!("Directory `{CACHE_DIR}` does not exist!"))
    }
}
