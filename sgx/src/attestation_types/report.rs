// SPDX-License-Identifier: Apache-2.0

//! Section 38.15
//! The REPORT structure is the output of the EREPORT instruction, and must be 512-Byte aligned.

use crate::types::{attr::Attributes, isv, misc::MiscSelect};

/// This struct is separated out from the Report to be usable by the Quote struct.
/// Table 38-21
#[derive(Default, Debug)]
#[repr(C)]
pub struct Body {
    /// The security version number of the processor
    pub cpusvn: [u8; 16],

    /// Bit vector specifying which extended features are saved to the
    /// MISC region of the SSA frame when an AEX occurs
    pub miscselect: MiscSelect,

    /// Reserved
    reserved0: [u32; 7],

    /// Attributes of the enclave (Section 38.7.1)
    pub attributes: Attributes,

    /// Value of SECS.MRENCLAVE
    pub mrenclave: [u8; 32],

    /// Reserved
    reserved1: [u32; 8],

    /// Value from SECS.MRSIGNER
    pub mrsigner: [u8; 32],

    /// Reserved
    reserved2: [u32; 24],

    /// Product ID of the enclave
    pub isvprodid: isv::ProdId,

    /// Security version number of the enclave
    pub isvsvn: isv::Svn,

    /// Reserved
    reserved3: [u32; 15],

    /// Data provided by the user and protected by the Report's MAC (Section 38.15.1)
    pub reportdata: [u16; 32],
}

/// Table 38-21
#[derive(Default, Debug)]
#[repr(C, align(512))]
pub struct Report {
    /// The body of the Report
    pub reportbody: Body,

    /// Value for key wear-out protection
    pub keyid: [u8; 32],

    /// MAC on the report using the Report Key
    pub mac: u128,

    /// Padding to 512 bytes
    padding: [u128; 5],
}

#[cfg(test)]
testaso! {
    struct Body: 4, 384 => {
        cpusvn: 0,
        miscselect: 16,
        reserved0: 20,
        attributes: 48,
        mrenclave: 64,
        reserved1: 96,
        mrsigner: 128,
        reserved2: 160,
        isvprodid: 256,
        isvsvn: 258,
        reserved3: 260,
        reportdata: 320
    }

    struct Report: 512, 512 => {
        reportbody: 0,
        keyid: 384,
        mac: 416,
        padding: 432
    }
}
