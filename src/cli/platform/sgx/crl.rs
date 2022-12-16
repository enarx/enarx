// SPDX-License-Identifier: Apache-2.0

use super::super::caching::fetch_file;

use std::fs::OpenOptions;
use std::io::Write;
use std::io::{self, ErrorKind};
use std::path::PathBuf;
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
        let mut dest_file = sgx_cache_dir()?;
        dest_file.push("crls.der");

        let crls = [
            fetch_file(CERT_CRL)
                .context(format!("fetching {CERT_CRL}"))
                .unwrap(),
            fetch_file(PROCESSOR_CRL)
                .context(format!("fetching {PROCESSOR_CRL}"))
                .unwrap(),
            fetch_file(PLATFORM_CRL)
                .context(format!("fetching {PLATFORM_CRL}"))
                .unwrap(),
        ];

        let crls = [
            CertificateList::from_der(&crls[0])?,
            CertificateList::from_der(&crls[1])?,
            CertificateList::from_der(&crls[2])?,
        ];

        let crls = crls
            .to_vec()
            .context("converting Intel CRLs to DER encoding")?;

        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dest_file)
            .context(format!(
                "opening destination file {dest_file:?} for saving Intel CRLs"
            ))?
            .write_all(&crls)
            .context(format!("writing Intel CRLs to file {dest_file:?}"))?;

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
