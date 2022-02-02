// SPDX-License-Identifier: Apache-2.0

//! Contains microarchitecture structures of SGX. Keep the functionality
//! minimal and stdlib free. Use the Intel SDM struct naming conventions,
//! instead of Rust naming conventions.
//!
//! Chapter 34 of the Intel SDM contains detailed documentation for these
//! structs.
//!
//! Guidelines for updating this file:
//! * Only use primitive types and arrays for the fields.
//! * Only use u8 arrays for reserved fields and padding.
//! * Document the structs at top-level but never the fields.
//! * Be super conservative when adding new functionality (e.g. trait
//!   implementations).

#![allow(non_camel_case_types)]
#![allow(missing_docs)]

use core::arch::asm;

/// Description of the local attestation source enclave contents.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct REPORT_PAYLOAD {
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

impl Default for REPORT_PAYLOAD {
    fn default() -> Self {
        REPORT_PAYLOAD {
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
#[repr(C, align(512))]
pub struct REPORT {
    pub body: REPORT_PAYLOAD,
    pub keyid: [u8; 32],
    pub mac: [u64; 2],
    padding: [u8; 80],
}

impl Default for REPORT {
    fn default() -> Self {
        REPORT {
            body: REPORT_PAYLOAD::default(),
            keyid: [0; 32],
            mac: [0, 0],
            padding: [0; 80],
        }
    }
}

/// Description of the target enclave used for the report key derivation in
/// EREPORT.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TARGETINFO {
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

impl Default for TARGETINFO {
    fn default() -> Self {
        TARGETINFO {
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

impl TARGETINFO {
    pub fn enclu_ereport(&self, reportdata: &[u8; 64]) -> REPORT {
        const EREPORT: usize = 0;

        // Purposely make an uninitialized memory block for the struct, as it
        // will be initialized by the CPU as the next step.
        let mut report = core::mem::MaybeUninit::<REPORT>::uninit();

        unsafe {
            asm!(
                "xchg       {RBX}, rbx",
                "enclu",
                "mov        rbx, {RBX}",

                RBX = inout(reg) self => _,
                in("rax") EREPORT,
                in("rcx") reportdata.as_ptr(),
                in("rdx") report.as_mut_ptr(),
            );
        }

        unsafe { report.assume_init() }
    }
}
