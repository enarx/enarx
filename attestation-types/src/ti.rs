// SPDX-License-Identifier: Apache-2.0

//! Report Target Info (Section 38.16)
//! The Target Info is used to identify the target enclave that will be able to cryptographically
//! verify the REPORT structure returned by the EREPORT leaf. Must be 512-byte aligned.

use sgx_types::{attr::Attributes, misc::MiscSelect};
#[cfg(test)]
use testing::testaso;

/// Table 38-22
#[derive(Debug)]
#[repr(C, align(512))]
pub struct TargetInfo {
    /// MRENCLAVE of the target enclave.
    pub mrenclave: [u8; 32],
    /// Attributes of the target enclave.
    pub attributes: Attributes,
    reserved0: u32,
    /// MiscSelect of the target enclave.
    pub misc: MiscSelect,
    reserved1: [u64; 32],
    reserved2: [u64; 25],
}

#[cfg(test)]
testaso! {
    struct TargetInfo: 512, 512 => {
        mrenclave: 0,
        attributes: 32,
        reserved0: 48,
        misc: 52,
        reserved1: 56,
        reserved2: 312
    }
}
