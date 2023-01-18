// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::snp::vcek::sev_cache_dir;
use crate::caching::fetch_crl_list;

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use clap::Args;
#[allow(unused_imports)]
use x509_cert::der::Decode as _; // required for Musl target
#[allow(unused_imports)]
use x509_cert::der::Encode as _; // required for Musl target

const GENOA: &str = "https://kdsintf.amd.com/vcek/v1/Genoa/crl";
const MILAN: &str = "https://kdsintf.amd.com/vcek/v1/Milan/crl";

/// Fetch AMD's Certificate Revocation Lists (CRLs),
/// saving as cached files in `/var/cache/amd-sev/` directory
#[derive(Args, Debug)]
pub struct CrlCache {}

impl CrlCache {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        let mut dest_file = sev_cache_dir()?;
        let mut crl_temp = dest_file.clone();
        dest_file.push("crls.der");
        crl_temp.push("crls.der.tmp");

        let crls = fetch_crl_list([GENOA.into(), MILAN.into()])?;
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&crl_temp)
            .context(format!(
                "opening destination file {crl_temp:?} for saving AMD CRLs"
            ))?
            .write_all(&crls)
            .context(format!("writing AMD CRLs to file {crl_temp:?}"))?;

        std::fs::rename(&crl_temp, &dest_file).context(format!(
            "Failed to move temporary CRL file {crl_temp:?} to final path {dest_file:?}"
        ))?;

        Ok(ExitCode::SUCCESS)
    }
}
