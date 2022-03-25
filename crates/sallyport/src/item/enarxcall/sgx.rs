// SPDX-License-Identifier: Apache-2.0

//! SGX microarchitecture-specific structures and constants.
//!
//! Only minimal functionality is provided by this module.
//!
//! Chapter 34 of the Intel SDM contains detailed documentation for these
//! structs.
//!
//! Guidelines for updating this file:
//! * Only use primitive types and arrays for the fields.
//! * Only use u8 arrays for reserved fields and padding.
//! * Document the structs at top-level but never the fields.

#![allow(missing_docs)]

use core::arch::asm;
use core::mem::{size_of, MaybeUninit};

/// `get_attestation` technology return value
///
/// See <https://github.com/enarx/enarx-keepldr/issues/31>
pub const TECH: usize = 2;

/// Description of the local attestation source enclave contents.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ReportPayload {
    pub cpusvn: [u64; 2],
    pub miscselect: u32,
    pub cet_attributes: u8,
    reserved1: [u8; 11],
    pub isvextnprodid: [u64; 2],
    pub attributes: [u64; 2],
    pub mrenclave: [u8; 32],
    reserved2: [u8; 32],
    pub mrsigner: [u8; 32],
    reserved3: [u8; 32],
    pub configid: [u8; 64],
    pub isvprodid: u16,
    pub isvsvn: u16,
    pub configsvn: u16,
    reserved4: [u8; 42],
    pub isvfamilyid: [u64; 2],
    pub reportdata: [u8; 64],
}

impl Default for ReportPayload {
    #[inline]
    fn default() -> Self {
        Self {
            cpusvn: [0, 0],
            miscselect: 0,
            cet_attributes: 0,
            reserved1: [0; 11],
            isvextnprodid: [0, 0],
            attributes: [0, 0],
            mrenclave: [0; 32],
            reserved2: [0; 32],
            mrsigner: [0; 32],
            reserved3: [0; 32],
            configid: [0; 64],
            isvprodid: 0,
            isvsvn: 0,
            configsvn: 0,
            reserved4: [0; 42],
            isvfamilyid: [0, 0],
            reportdata: [0; 64],
        }
    }
}

/// Description of the local attestation source enclave contents with the CMAC
/// signed with the report key. Used by the target enclave to verify the source
/// enclave by grabbing the report key with EGETKEY and calculating CMAC.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(512))]
pub struct Report {
    pub payload: ReportPayload,
    pub keyid: [u8; 32],
    pub mac: [u64; 2],
    padding: [u8; 80],
}

impl Default for Report {
    #[inline]
    fn default() -> Self {
        Self {
            payload: ReportPayload::default(),
            keyid: [0; 32],
            mac: [0, 0],
            padding: [0; 80],
        }
    }
}

impl AsRef<[u8; size_of::<Report>()]> for Report {
    #[inline]
    fn as_ref(&self) -> &[u8; size_of::<Report>()] {
        unsafe { &*(self as *const _ as *const _) }
    }
}

/// Description of the target enclave used for the report key derivation in
/// EREPORT.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(512))]
pub struct TargetInfo {
    pub mrenclave: [u8; 32],
    pub attributes: [u64; 2],
    pub cet_attributes: u8,
    reserved1: [u8; 1],
    pub configsvn: u16,
    pub miscselect: u32,
    reserved2: [u8; 8],
    pub configid: [u8; 64],
    reserved3: [u8; 384],
}

impl Default for TargetInfo {
    #[inline]
    fn default() -> Self {
        Self {
            mrenclave: [0; 32],
            attributes: [0, 0],
            cet_attributes: 0,
            reserved1: [0; 1],
            configsvn: 0,
            miscselect: 0,
            reserved2: [0; 8],
            configid: [0; 64],
            reserved3: [0; 384],
        }
    }
}

impl AsMut<[u8; size_of::<TargetInfo>()]> for TargetInfo {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8; size_of::<TargetInfo>()] {
        unsafe { &mut *(self as *mut _ as *mut _) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(128))]
/// Pass information from the source enclave to the target enclave
pub struct ReportData(pub [u8; 64]);

impl Default for ReportData {
    #[inline]
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl TargetInfo {
    #[inline]
    pub fn enclu_ereport(&self, reportdata: &ReportData) -> Report {
        const EREPORT: usize = 0;

        // Purposely make an uninitialized memory block for the struct, as it
        // will be initialized by the CPU as the next step.
        let mut report = MaybeUninit::<Report>::uninit();

        // In Rust inline assembly rbx is not preserved by the compiler, even
        // when part of the input list. It is one of the callee saved registers
        // dictated by:
        //
        // https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf
        unsafe {
            asm!(
                "xchg       {RBX}, rbx",
                "enclu",
                "mov        rbx, {RBX}",

                RBX = inout(reg) self => _,
                in("rax") EREPORT,
                in("rcx") reportdata.0.as_ptr(),
                in("rdx") report.as_mut_ptr(),
            );
        }

        unsafe { report.assume_init() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use testaso::testaso;

    testaso! {
        struct ReportPayload: 8, 384 => {
            cpusvn: 0,
            miscselect: 16,
            cet_attributes: 20,
            reserved1: 21,
            isvextnprodid: 32,
            attributes: 48,
            mrenclave: 64,
            reserved2: 96,
            mrsigner: 128,
            reserved3: 160,
            configid: 192,
            isvprodid: 256,
            isvsvn: 258,
            configsvn: 260,
            reserved4: 262,
            isvfamilyid: 304,
            reportdata: 320
        }

        struct Report: 512, 512 => {
            payload: 0,
            keyid: 384,
            mac: 416,
            padding: 432
        }

        struct TargetInfo: 512, 512 => {
            mrenclave: 0,
            attributes: 32,
            cet_attributes: 48,
            reserved1: 49,
            configsvn: 50,
            miscselect: 52,
            reserved2: 56,
            configid: 64,
            reserved3: 128
        }
    }
}
