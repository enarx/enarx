// SPDX-License-Identifier: Apache-2.0

//! The Quote structure is used to provide proof to an off-platform entity that an application
//! enclave is running with Intel SGX protections on a trusted Intel SGX enabled platform.
//! See Section A.4 in the following link for all types in this module:
//! https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf

pub mod quoteheader;
pub mod sigdata;

use super::report::{Body, ReportError};
use quoteheader::QuoteHeader;
use sigdata::SigData;

use core::{convert::TryFrom, fmt};

// The length of an ECDSA signature is 64 bytes. This value must be 4 bytes.
const ECDSASIGLEN: u32 = 64;

// The PCK hash is a SHA256 hash, so has a length of 32 bytes.
const PCK_HASH_LEN: usize = 32;

// These consts are either lengths in bytes or indices of starting bytes in a
// Quote byte vector based on the SGX spec. Note that Reports are embedded
// in the Quote in several fields (in ISV Enclave Report for the attesting enclave,
// as well as in the Quote Signature for the QE verifying the ISV Enclave Report).
// The REPORTDATA_START refers to the starting index of a ReportData field from
// the beginning of any Report, whereas QE_REPORTDATA_START refers to the starting
// index of the ReportData in the QE Report embedded in the Quote Signature and the
// offset is therefore from the beginning of the Quote.
//
// Quote
// |-----------
// | -- QuoteHeader (48 bytes)
// |    | -- ...
// |
// | -- ISV Enclave Report (384 bytes)
// |    | -- ...
// |    | -- ReportData (at offset 320 from Report start)
// |
// | -- Quote Sig Data Len (4 bytes)
// |
// | -- Quote Signature (length specified in Quote Sig Data Len)
// |    | -- ISV Enclave Report Sig (64 bytes)
// |    | -- AK Pub (64 bytes)
// |    | -- QE Report (384 bytes)
// |    |    | -- ...
// |    |    | -- ReportData (at offset 320 from Report start)
// |    | -- ...
// |____________
//

// Report Layout consts
const REPORTDATA_START: usize = 320;

// Quote Layout consts
const QUOTE_HEADER_LEN: usize = 48;
const ISV_ENCLAVE_REPORT_LEN: usize = 384;
const QUOTE_SIG_DATA_LEN_LEN: usize = 4;
const QUOTE_SIG_START: usize = 436;

// Quote Signature Layout consts
const ISV_ENCLAVE_REPORT_SIG_LEN: usize = 64;
const ATT_KEY_PUB_LEN: usize = 64;
const QE_REPORT_START: usize = QUOTE_SIG_START + ISV_ENCLAVE_REPORT_SIG_LEN + ATT_KEY_PUB_LEN;
const QE_REPORTDATA_START: usize = QE_REPORT_START + REPORTDATA_START;

#[derive(Clone, Debug)]
/// Error type for Quote module
pub struct QuoteError(pub String);

impl fmt::Display for QuoteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl std::error::Error for QuoteError {}

impl From<ReportError> for QuoteError {
    fn from(_: ReportError) -> Self {
        QuoteError("Report error".to_string())
    }
}

/// Wrapper struct for the u32 indicating the signature data length
/// (described in A.4).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SigDataLen(u32);

impl From<u32> for SigDataLen {
    fn from(val: u32) -> Self {
        SigDataLen(val)
    }
}

impl Default for SigDataLen {
    fn default() -> Self {
        SigDataLen(ECDSASIGLEN)
    }
}

impl From<&[u8; 4]> for SigDataLen {
    fn from(bytes: &[u8; 4]) -> Self {
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&bytes[0..4]);
        let len = u32::from_le_bytes(tmp);
        SigDataLen::from(len)
    }
}

/// Section A.4
/// All integer fields are in little endian.
#[derive(Default, Debug)]
#[repr(C, align(4))]
pub struct Quote {
    /// Header for Quote structure; transparent to the user.
    pub header: QuoteHeader,

    /// Report of the atteste enclave.
    isv_enclave_report: Body,

    /// Size of the Signature Data field.
    sig_data_len: SigDataLen,

    /// Variable-length data containing the signature and
    /// supporting data.
    sig_data: SigData,
}

// The size of the Quote is not known at compile time. It is specified in the data itself.
impl TryFrom<&[u8]> for Quote {
    type Error = QuoteError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // Check validity of Quote length
        let mut sig_data_len_bytes = [0u8; QUOTE_SIG_DATA_LEN_LEN];
        if bytes.len() < 436 {
            return Err(QuoteError(
                "Insufficient Quote length; no sig data len specified".to_string(),
            ));
        }
        sig_data_len_bytes.copy_from_slice(&bytes[432..436]);
        let sd_len = u32::from_le_bytes(sig_data_len_bytes);

        let expected_quote_len = QUOTE_SIG_START + sd_len as usize;

        if bytes.len() < expected_quote_len {
            return Err(QuoteError(
                "Insufficient Quote length; cannot convert from byte slice".to_string(),
            ));
        }

        // Convert the Quote from byte slice
        let mut header = [0u8; QUOTE_HEADER_LEN];
        header.copy_from_slice(&bytes[0..QUOTE_HEADER_LEN]);

        let mut body = [0u8; ISV_ENCLAVE_REPORT_LEN];
        body.copy_from_slice(&bytes[QUOTE_HEADER_LEN..(QUOTE_HEADER_LEN + ISV_ENCLAVE_REPORT_LEN)]);

        Ok(Self {
            header: QuoteHeader::try_from(&header)?,
            isv_enclave_report: Body::try_from(&body)?,
            sig_data_len: SigDataLen::from(sd_len),
            sig_data: SigData::try_from(&bytes[QUOTE_SIG_START..expected_quote_len])?,
        })
    }
}

impl Quote {
    /// This vector of the Quote Header and ISV Enclave Report is the material signed
    /// by the Quoting Enclave's Attestation Key and should be returned in raw form to
    /// verify the Attestation Key's signature. Specifically, the header's version
    /// number should also be kept intact in the vector, rather than being abstracted
    /// into the Header enum.
    pub fn raw_header_and_body(quote: &[u8]) -> Result<&[u8], QuoteError> {
        if quote.len() < QUOTE_HEADER_LEN + ISV_ENCLAVE_REPORT_LEN {
            return Err(QuoteError(
                "Insufficient Quote length; cannot return raw header and body".to_string(),
            ));
        }

        Ok(&quote[0..QUOTE_HEADER_LEN + ISV_ENCLAVE_REPORT_LEN])
    }

    /// The Report Data of the QE Report holds a SHA256 hash of (ECDSA Attestation Key || QE
    /// Authentication data) || 32-0x00's. This hash must be verified for attestation.
    /// The Report comes after the ISV Enclave Report Signature and Attestation Public Key in the
    /// Quote Signature. The structure of the QE Report in the Quote Signature is identical
    /// to the structure of any enclave's Report, so the Report Data begins at byte 320 of the Report.
    pub fn raw_pck_hash(quote: &[u8]) -> Result<&[u8], QuoteError> {
        if quote.len() < QE_REPORTDATA_START + PCK_HASH_LEN {
            return Err(QuoteError(
                "Insufficient Quote length; cannot return raw PCK hash".to_string(),
            ));
        }

        Ok(&quote[QE_REPORTDATA_START..QE_REPORTDATA_START + PCK_HASH_LEN])
    }

    /// Retrieves Quote Header
    pub fn header(&self) -> &QuoteHeader {
        &self.header
    }

    /// Retrieves Quote Body
    pub fn body(&self) -> &Body {
        &self.isv_enclave_report
    }

    /// Retrieves Quote's sig length
    pub fn siglen(&self) -> &SigDataLen {
        &self.sig_data_len
    }

    /// Retrieves Quote's signature data
    pub fn sigdata(&self) -> &SigData {
        &self.sig_data
    }
}
