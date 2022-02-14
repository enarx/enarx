// SPDX-License-Identifier: Apache-2.0

//! The QuoteHeader is part of the Quote structure. See the Quote module for more.

use super::QuoteError;
use core::convert::TryFrom;

/// The Quote version for DCAP is 3. Must be 2 bytes.
pub const VERSION: u16 = 3;

/// Intel's Vendor ID, as specified in A.4, Table 3. Must be 16 bytes.
pub const INTELVID: [u8; 16] = [
    0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
];

/// The type of Attestation Key used to sign the Report.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

impl TryFrom<u16> for AttestationKeyType {
    type Error = QuoteError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(AttestationKeyType::ECDSA256P256),
            3 => Ok(AttestationKeyType::ECDSA384P384),
            _ => Err(QuoteError(format!(
                "Unknown AttestationKeyType value: {}",
                value
            ))),
        }
    }
}

/// Unlike the other parts of the Quote, this structure
/// is transparent to the user.
/// Section A.4, Table 3
#[derive(Debug, Clone, Copy)]
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

impl TryFrom<&[u8; 48]> for QuoteHeader {
    type Error = QuoteError;

    fn try_from(bytes: &[u8; 48]) -> Result<Self, Self::Error> {
        let mut tmp = [0u8; 2];

        tmp.copy_from_slice(&bytes[0..2]);
        let version = u16::from_le_bytes(tmp);
        if version != VERSION {
            return Err(QuoteError(
                    format!("Incorrect Quote version, expected: {}, actual: {}; cannot convert bytes to QuoteHeader", 
                VERSION, version)));
        }

        tmp.copy_from_slice(&bytes[2..4]);
        let att_key_type = AttestationKeyType::try_from(u16::from_le_bytes(tmp))?;
        if att_key_type != AttestationKeyType::default() {
            return Err(QuoteError(
                    format!("Incorrect Quote key type, expected: {}, actual: {}; cannot convert bytes to QuoteHeader", 
                AttestationKeyType::default() as u16, att_key_type as u16)));
        }

        tmp.copy_from_slice(&bytes[8..10]);
        let qe_svn = u16::from_le_bytes(tmp);

        tmp.copy_from_slice(&bytes[10..12]);
        let pce_svn = u16::from_le_bytes(tmp);

        let mut qe_vendor_id = [0u8; 16];
        qe_vendor_id.copy_from_slice(&bytes[12..28]);

        let mut user_data = [0u8; 20];
        user_data.copy_from_slice(&bytes[28..48]);

        Ok(Self {
            version,
            att_key_type,
            qe_svn,
            pce_svn,
            qe_vendor_id,
            user_data,
            ..Default::default()
        })
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
