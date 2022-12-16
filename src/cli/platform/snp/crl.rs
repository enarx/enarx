// SPDX-License-Identifier: Apache-2.0

use super::super::caching::fetch_file;
use crate::backend::sev::snp::vcek::sev_cache_dir;

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use clap::Args;
#[allow(unused_imports)]
use der::{Decode, Encode};
use x509_cert::crl::CertificateList;
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
        dest_file.push("crls.der");

        let crls = [
            fetch_file(GENOA).context(format!("fetching {GENOA}"))?,
            fetch_file(MILAN).context(format!("fetching {MILAN}"))?,
        ];

        let crls = [
            CertificateList::from_der(&crls[0])?,
            CertificateList::from_der(&crls[1])?,
        ];

        let crls = crls
            .to_vec()
            .context("converting AMD CRLs to DER encoding")?;

        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dest_file)
            .context(format!(
                "opening destination file {dest_file:?} for saving AMD CRLs"
            ))?
            .write_all(&crls)
            .context(format!("writing AMD CRLs to file {dest_file:?}"))?;

        Ok(ExitCode::SUCCESS)
    }
}
