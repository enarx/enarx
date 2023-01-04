// SPDX-License-Identifier: Apache-2.0

use crate::backend::sgx::{TcbPackage, FMSPC_PATH, TCB_PATH};

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use std::process::ExitCode;

use anyhow::{bail, Context};
use clap::Args;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use percent_encoding::percent_decode;
use x509_cert::Certificate;

const FMSPC_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert";
const TCB_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/tcb";
const PCKID_CSV_PATH: &str = "/var/cache/intel-sgx/pckid_retrieval.csv";

/// Fetch the prerequisites for fetching the TCB report from Intel
// * Run Intel's `PCKIDRetrievalTool`
// * Parse the resulting pckid_retrieval.csv for EncryptedPPID, PCE_ID, CPUSVNPCE, ISVSVN, QE_ID
// * Use these fields to fetch FMSPC from https://api.trustedservices.intel.com/sgx/certification/v4/pckcert
// * Use the FMSPC to fetch the actual TCB report from https://api.trustedservices.intel.com/sgx/certification/v4/tcb
// SGX API documentation: https://api.portal.trustedservices.intel.com/documentation
// SGX cert extension documentation: https://download.01.org/intel-sgx/dcap-1.1/linux/docs/Intel_SGX_PCK_Certificate_CRL_Spec-1.1.pdf
// Save the resulting files in the `/var/cache/intel-sgx/` directory
#[derive(Args, Debug)]
pub struct PckCache {}

impl PckCache {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        if !Path::new(PCKID_CSV_PATH).exists() {
            Command::new("PCKIDRetrievalTool")
                .arg("-f")
                .arg(PCKID_CSV_PATH)
                .spawn()
                .expect("Could not run PCKIDRetrievalTool, is it in the $PATH? Are you root?")
                .wait()?;
        }

        let report = std::fs::read_to_string(PCKID_CSV_PATH)?;
        let report_parts: Vec<&str> = report.split(',').collect();
        let url = format!(
            "{FMSPC_URL}/?encrypted_ppid={}&cpusvn={}&pcesvn={}&pceid={}",
            report_parts[0], report_parts[2], report_parts[3], report_parts[1]
        );

        let (pck_cert, _) = fetch_file(&url).context("Failed to fetch PCK certificate")?;
        let mut pck_cursor = std::io::Cursor::new(pck_cert);

        let pck_cert = rustls_pemfile::certs(&mut pck_cursor)
            .context("Failed to PEM-decode PCK certificate")?;

        let pck_cert =
            Certificate::from_der(&pck_cert[0]).context("Failed to DER-decode PCK certificate")?;

        let fmspc = decode_extension(&pck_cert)?;
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(FMSPC_PATH)
            .context(format!(
                "opening destination file {FMSPC_PATH} for saving Intel FMSPC"
            ))?
            .write_all(fmspc.as_bytes())
            .context(format!("writing Intel FMSPC to file {FMSPC_PATH}"))?;

        Ok(ExitCode::SUCCESS)
    }
}

fn decode_extension(cert: &Certificate) -> anyhow::Result<String> {
    const SGX_EXT_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
    const FMSPC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");
    const FMSPC_OID_LEN: usize = 10;

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for extension in extensions.iter() {
            if extension.extn_id == SGX_EXT_OID {
                let offset = extension
                    .extn_value
                    .windows(FMSPC_OID_LEN)
                    .position(|window| window == FMSPC_OID.as_bytes());
                if let Some(offset) = offset {
                    // Index into the extension bytes at the offset + OID size + 2
                    // The extra +2 gets us past the ASN.1 header for these bytes.
                    let fmspc = &extension.extn_value
                        [offset + FMSPC_OID_LEN + 2..offset + FMSPC_OID_LEN + 6 + 2];
                    return Ok(hex::encode_upper(fmspc));
                }
            }
        }
    }
    Err(anyhow::Error::msg(
        "failed to parse SGX certificate extensions, FMSPC not found.",
    ))
}

fn fetch_file(url: &str) -> anyhow::Result<(Vec<u8>, Option<String>)> {
    let response = ureq::get(url).call().context(format!("retrieving {url}"))?;

    let tcb_cert_chain = response.header("tcb-info-issuer-chain").map(String::from);

    let mut reader = response.into_reader();

    let mut bytes = vec![];
    reader
        .read_to_end(&mut bytes)
        .context("reading bytes buffer")?;
    Ok((bytes, tcb_cert_chain))
}

/// Fetch the TCB report from Intel
#[derive(Args, Debug)]
pub struct TcbCache {}

impl TcbCache {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        if !Path::new(FMSPC_PATH).exists() {
            bail!("Cannot read {FMSPC_PATH}, please run `enarx platform sgx cache-pck`")
        }

        let fmspc =
            std::fs::read_to_string(FMSPC_PATH).context(format!("Failed to read {FMSPC_PATH}"))?;

        let url = format!("{TCB_URL}?fmspc={fmspc}");
        let (tcb_report, tcb_cert_chain) =
            fetch_file(&url).context("Failed to fetch Intel TCB report")?;

        if tcb_cert_chain.is_none() {
            bail!("Did not receive Intel TCB signing certificates in HTTP response header");
        }

        let tcb_cert_chain = tcb_cert_chain.unwrap();
        // Decode certs from HTTP-friendly characters
        let tcb_cert_chain = String::from(percent_decode(tcb_cert_chain.as_bytes()).decode_utf8()?);

        let mut tcb_cert_vec = vec![];
        let mut certs_cursor = std::io::Cursor::new(tcb_cert_chain);
        let tcb_certs = rustls_pemfile::certs(&mut certs_cursor)
            .context("Failed to PEM-decode TCB certificate chain")?;

        for cert in tcb_certs.iter() {
            tcb_cert_vec.push(
                Certificate::from_der(cert)
                    .context("Failed to DER-encode TCB certificate chain")?,
            );
        }

        let tcb_package = TcbPackage {
            crts: tcb_cert_vec,
            report: &tcb_report,
        };

        let tcb_package = tcb_package
            .to_vec()
            .context("Failed to encode TCB certs and report to DER")?;

        let mut tcb_temp = String::from(TCB_PATH);
        tcb_temp.push_str(".tmp");

        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tcb_temp)
            .context(format!(
                "opening destination file {tcb_temp} for saving Intel TCB report"
            ))?
            .write_all(&tcb_package)
            .context(format!("writing Intel TCB report to file {tcb_temp}"))?;

        std::fs::rename(&tcb_temp, TCB_PATH).context(format!(
            "Failed to move temporary TCB {tcb_temp} to final path {TCB_PATH}"
        ))?;

        Ok(ExitCode::SUCCESS)
    }
}
