// SPDX-License-Identifier: Apache-2.0

//! The Quote structure is used to provide proof to an off-platform entity that an application
//! enclave is running with Intel SGX protections on a trusted Intel SGX enabled platform.
//! See Section A.4 in the following link for all types in this module:
//! https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf

use super::report::Body;
use std::vec::Vec;

/// The Quote version for DCAP is 3. Must be 2 bytes.
pub const VERSION: u16 = 3;

/// The length of an ECDSA signature is 64 bytes. This value must be 4 bytes.
pub const ECDSASIGLEN: u32 = 64;

/// Intel's Vendor ID, as specified in A.4, Table 3. Must be 16 bytes.
pub const INTELVID: [u8; 16] = [
    0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
];

/// Section A.4, Table 9
#[repr(u16)]
pub enum CertDataType {
    /// Byte array that contains concatenation of PPID, CPUSVN,
    /// PCESVN (LE), PCEID (LE)
    PpidPlaintext = 1,

    /// Byte array that contains concatenation of PPID encrypted
    /// using RSA-2048-OAEP, CPUSVN,  PCESVN (LE), PCEID (LE)
    PpidRSA2048OAEP = 2,

    /// Byte array that contains concatenation of PPID encrypted
    /// using RSA-3072-OAEP, CPUSVN, PCESVN (LE), PCEID (LE)
    PpidRSA3072OAEP = 3,

    /// PCK Leaf Certificate
    PCKLeafCert = 4,

    /// Concatenated PCK Cert Chain  (PEM formatted).
    /// PCK Leaf Cert||Intermediate CA Cert||Root CA Cert
    PCKCertChain = 5,

    /// Intel SGX Quote (not supported).
    Quote = 6,

    /// Platform Manifest (not supported).
    Manifest = 7,
}

impl Default for CertDataType {
    fn default() -> Self {
        Self::PCKCertChain
    }
}

/// ECDSA  signature, the r component followed by the
/// s component, 2 x 32 bytes.
/// A.4, Table 6
#[derive(Default)]
#[repr(C)]
pub struct ECDSAP256Sig {
    /// r component
    pub r: [u8; 32],

    /// s component
    pub s: [u8; 32],
}

/// EC KT-I Public Key, the x-coordinate followed by
/// the y-coordinate (on the RFC 6090P-256 curve),
/// 2 x 32 bytes.
/// A.4, Table 7
#[derive(Default)]
#[repr(C)]
pub struct ECDSAPubKey {
    /// x coordinate
    pub x: [u8; 32],

    /// y coordinate
    pub y: [u8; 32],
}

/// A.4, Table 4
#[derive(Default)]
#[repr(C)]
pub struct SigData {
    isv_enclave_report_sig: ECDSAP256Sig,
    ecdsa_attestation_key: ECDSAPubKey,
    qe_report: Body,
    qe_report_sig: ECDSAP256Sig,
    qe_auth: Vec<u8>,
    qe_cert_data_type: CertDataType,
    qe_cert_data: Vec<u8>,
}

/// The type of Attestation Key used to sign the Report.
#[repr(u16)]
pub enum AttestationKeyType {
    /// ECDSA-256-with-P-256 curve
    ECDSA256P256 = 2,

    /// ECDSA-384-with-P-384 curve; not supported
    ECDSA384P384 = 3,
}

impl Default for AttestationKeyType {
    fn default() -> Self {
        AttestationKeyType::ECDSA256P256
    }
}

/// Unlike the other parts of the Quote, this structure
/// is transparent to the user.
/// Section A.4, Table 3
#[repr(C)]
pub struct QuoteHeader {
    /// Version of Quote structure, 3 in the ECDSA case.
    pub version: u16,

    /// Type of attestation key used. Only one type is currently supported:
    /// 2 (ECDSA-256-with-P-256-curve).
    pub att_key_type: AttestationKeyType,

    /// Reserved.
    reserved: u32,

    /// Security version of the QE.
    pub qe_svn: u16,

    /// Security version of the Provisioning Cerfitication Enclave.
    pub pce_svn: u16,

    /// ID of the QE vendor.
    pub qe_vendor_id: [u8; 16],

    /// Custom user-defined data. For the Intel DCAP library, the first 16 bytes
    /// contain a QE identifier used to link a PCK Cert to an Enc(PPID). This
    /// identifier is consistent for every quote generated with this QE on this
    /// platform.
    pub user_data: [u8; 20],
}

impl Default for QuoteHeader {
    fn default() -> Self {
        Self {
            version: VERSION,
            att_key_type: Default::default(),
            reserved: Default::default(),
            qe_svn: Default::default(),
            pce_svn: Default::default(),
            qe_vendor_id: INTELVID,
            user_data: [0u8; 20],
        }
    }
}

/// Section A.4
/// All integer fields are in little endian.
#[repr(C, align(4))]
pub struct Quote {
    /// Header for Quote structure; transparent to the user.
    pub header: QuoteHeader,

    /// Report of the atteste enclave.
    isv_enclave_report: Body,

    /// Size of the Signature Data field.
    sig_data_len: u32,

    /// Variable-length data containing the signature and
    /// supporting data.
    sig_data: SigData,
}

impl Default for Quote {
    fn default() -> Self {
        Self {
            header: Default::default(),
            isv_enclave_report: Default::default(),
            sig_data_len: ECDSASIGLEN,
            sig_data: Default::default(),
        }
    }
}

#[cfg(test)]
testaso! {
    struct QuoteHeader: 4, 48 => {
        version: 0,
        att_key_type: 2,
        reserved: 4,
        qe_svn: 8,
        pce_svn: 10,
        qe_vendor_id: 12,
        user_data: 28
    }
}
