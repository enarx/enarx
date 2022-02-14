// SPDX-License-Identifier: Apache-2.0

//! Report Target Info (Section 38.16)
//! The Target Info is used to identify the target enclave that will be able to cryptographically
//! verify the REPORT structure returned by the EREPORT leaf. Must be 512-byte aligned.

use crate::types::{attr::Attributes, misc::MiscSelect};
use core::default::Default;

/// Table 38-22
#[derive(Default, Debug, Clone, Copy)]
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

#[derive(Clone, Copy)]
#[repr(C, align(128))]
/// Pass information from the source enclave to the target enclave
pub struct ReportData(pub [u8; 64]);

impl Default for ReportData {
    fn default() -> Self {
        ReportData([0u8; 64])
    }
}

#[cfg(feature = "asm")]
impl TargetInfo {
    /// Generate a report to the specified target with the included data.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it executes the `enclu[EREPORT]`
    /// instruction which is only available when the processor is in enclave
    /// mode.
    pub unsafe fn get_report(&self, data: &ReportData) -> crate::attestation_types::report::Report {
        use crate::attestation_types::report;

        const EREPORT: usize = 0;

        let mut report = core::mem::MaybeUninit::<report::Report>::uninit();

        asm!(
            "xchg {RBX}, rbx",
            "enclu",
            "mov rbx, {RBX}",

            RBX = inout(reg) self => _,
            in("rax") EREPORT,
            in("rcx") data.0.as_ptr(),
            in("rdx") report.as_mut_ptr(),
        );

        report.assume_init()
    }
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
