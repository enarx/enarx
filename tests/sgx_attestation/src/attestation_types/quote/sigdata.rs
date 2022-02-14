// SPDX-License-Identifier: Apache-2.0

//! The SigData structure is part of the Quote structure. For more, see the Quote module.

use super::QuoteError;
use crate::attestation_types::report::Body;
use std::{convert::TryFrom, fmt, vec::Vec};

/// ECDSA  signature, the r component followed by the
/// s component, 2 x 32 bytes.
/// A.4, Table 6
#[derive(Default, Clone, Copy, Debug)]
#[repr(C)]
pub struct ECDSAP256Sig {
    /// r component
    pub r: [u8; 32],

    /// s component
    pub s: [u8; 32],
}

impl From<&[u8; 64]> for ECDSAP256Sig {
    fn from(bytes: &[u8; 64]) -> Self {
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);

        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..64]);

        Self { r, s }
    }
}

impl ECDSAP256Sig {
    /// Returns Vec<u8> of r component followed by s component
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(&self.r);
        vec.extend(&self.s);
        vec
    }
}

/// EC KT-I Public Key, the x-coordinate followed by
/// the y-coordinate (on the RFC 6090P-256 curve),
/// 2 x 32 bytes.
/// A.4, Table 7
#[derive(Default, Clone, Copy, Debug)]
#[repr(C)]
pub struct ECDSAPubKey {
    /// x coordinate
    pub x: [u8; 32],

    /// y coordinate
    pub y: [u8; 32],
}

impl From<&[u8; 64]> for ECDSAPubKey {
    fn from(bytes: &[u8; 64]) -> Self {
        let mut x = [0u8; 32];
        x.copy_from_slice(&bytes[0..32]);

        let mut y = [0u8; 32];
        y.copy_from_slice(&bytes[32..64]);

        Self { x, y }
    }
}

impl ECDSAPubKey {
    /// Returns a Vec<u8> of the x coordinate followed by the y coordinate
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(&self.x);
        vec.extend(&self.y);
        vec
    }
}

/// Section A.4, Table 9
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
        Self::PCKLeafCert
    }
}

impl TryFrom<u16> for CertDataType {
    type Error = QuoteError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CertDataType::PpidPlaintext),
            2 => Ok(CertDataType::PpidRSA2048OAEP),
            3 => Ok(CertDataType::PpidRSA3072OAEP),
            4 => Ok(CertDataType::PCKLeafCert),
            5 => Ok(CertDataType::PCKCertChain),
            6 => Ok(CertDataType::Quote),
            7 => Ok(CertDataType::Manifest),
            _ => Err(QuoteError(format!("Unknown Cert Data type: {}", value))),
        }
    }
}

impl fmt::Display for CertDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CertDataType::PpidPlaintext => write!(f, "PpidPlaintext"),
            CertDataType::PpidRSA2048OAEP => write!(f, "PpidRSA2048OAEP"),
            CertDataType::PpidRSA3072OAEP => write!(f, "PpidRSA3072)AEP"),
            CertDataType::PCKLeafCert => write!(f, "PCKLeafCert"),
            CertDataType::PCKCertChain => write!(f, "PCKCertChain"),
            CertDataType::Quote => write!(f, "Quote"),
            CertDataType::Manifest => write!(f, "Manifest"),
        }
    }
}

/// A.4, Table 4
#[derive(Default, Debug)]
#[repr(C)]
pub struct SigData {
    isv_enclave_report_sig: ECDSAP256Sig,
    ecdsa_attestation_key: ECDSAPubKey,
    qe_report: Body,
    qe_report_sig: ECDSAP256Sig,
    qe_auth: Vec<u8>,
    qe_cert_data_type: CertDataType,
    qe_cert_data_len: u32,
    qe_cert_data: Vec<u8>,
}

// The size of SigData is not known at compile time. It is specified in the data itself.
impl TryFrom<&[u8]> for SigData {
    type Error = QuoteError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut tmp = [0u8; 64];
        tmp.copy_from_slice(&bytes[0..64]);
        let isv_enclave_report_sig = ECDSAP256Sig::from(&tmp);

        tmp.copy_from_slice(&bytes[64..128]);
        let ecdsa_attestation_key = ECDSAPubKey::from(&tmp);

        let mut body = [0u8; 384];
        body.copy_from_slice(&bytes[128..512]);
        let qe_report = Body::try_from(&body)?;

        tmp.copy_from_slice(&bytes[512..576]);
        let qe_report_sig = ECDSAP256Sig::from(&tmp);

        // QE Auth Data length is variable, specified in &bytes[576..578]
        let mut qe_auth_len_bytes = [0u8; 2];
        qe_auth_len_bytes.copy_from_slice(&bytes[576..578]);
        let qe_auth_len: usize = u16::from_le_bytes(qe_auth_len_bytes).into();
        let mut qe_auth = vec![0u8; qe_auth_len];
        let qe_auth_end = 578usize + qe_auth_len;
        qe_auth.copy_from_slice(&bytes[578..qe_auth_end]);

        // Cert Data beginning and length is variable
        let mut qe_cert_data_type_bytes = [0u8; 2];
        qe_cert_data_type_bytes.copy_from_slice(&bytes[qe_auth_end..(qe_auth_end + 2)]);
        let qe_cert_data_type =
            CertDataType::try_from(u16::from_le_bytes(qe_cert_data_type_bytes))?;
        /*
                if qe_cert_data_type != CertDataType::PCKCertChain {
                    return Err(QuoteError(format!(
                        "Expected CertDataType::PCKCertChain, got: {}",
                        qe_cert_data_type
                    )));
                }
        */
        if qe_cert_data_type != CertDataType::PpidRSA3072OAEP {
            #[warn(dead_code)]
            const WARNING: &str =
                "Please recheck, that we want PpidRSA3072OAEP and not a PCKCertChain";

            return Err(QuoteError(format!(
                "Expected CertDataType::PpidRSA3072, got: {}",
                qe_cert_data_type
            )));
        }

        let cert_data_len_start = qe_auth_end + 2;
        let mut cert_data_len_bytes = [0u8; 4];
        cert_data_len_bytes.copy_from_slice(&bytes[cert_data_len_start..(cert_data_len_start + 4)]);
        let qe_cert_data_len = u32::from_le_bytes(cert_data_len_bytes);
        let cert_data_start = cert_data_len_start + 4;
        let mut qe_cert_data = vec![0u8; qe_cert_data_len as usize];
        qe_cert_data.copy_from_slice(
            &bytes[cert_data_start..(cert_data_start + qe_cert_data_len as usize)],
        );

        Ok(Self {
            isv_enclave_report_sig,
            ecdsa_attestation_key,
            qe_report,
            qe_report_sig,
            qe_auth,
            qe_cert_data_type,
            qe_cert_data_len,
            qe_cert_data,
        })
    }
}

impl SigData {
    /// Retrieve Report Signature
    pub fn report_sig(&self) -> &ECDSAP256Sig {
        &self.isv_enclave_report_sig
    }

    /// Retrieve Attestation Key used to sign Report
    pub fn attkey(&self) -> &ECDSAPubKey {
        &self.ecdsa_attestation_key
    }

    /// Retrieve QE Report of the QE that signed the Report
    pub fn qe_report(&self) -> &Body {
        &self.qe_report
    }

    /// Retrieve the QE Report Signature
    pub fn qe_report_sig(&self) -> &ECDSAP256Sig {
        &self.qe_report_sig
    }

    /// Retrieve the QE Auth
    pub fn qe_auth(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(&self.qe_auth);
        v
    }

    /// Retrieve the QE Cert Data type
    pub fn qe_cert_data_type(&self) -> &CertDataType {
        &self.qe_cert_data_type
    }

    /// Retrieve the QE Cert Data length
    pub fn get_qe_cert_data_len(&self) -> u32 {
        self.qe_cert_data_len
    }

    /// Retrieve the QE Cert Data
    pub fn qe_cert_data_vec(&self) -> Vec<u8> {
        self.qe_cert_data.clone()
    }
}
