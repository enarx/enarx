// SPDX-License-Identifier: Apache-2.0

//! SNP specific modules and functions

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::VirtAddr;

pub use cpuid_page::{cpuid, cpuid_count, get_cpuid_max};

use crate::snp::Error::{FailInput, FailSizeMismatch, Unknown};

pub mod attestation;
pub mod cpuid_page;
pub mod ghcb;
pub mod secrets_page;

/// The C-Bit mask indicating encrypted physical addresses
pub static C_BIT_MASK: AtomicU64 = AtomicU64::new(0);

/// Get the SEV C-Bit mask
#[inline(always)]
pub fn get_cbit_mask() -> u64 {
    C_BIT_MASK.load(Ordering::Relaxed)
}

/// Test, if SEV-SNP is enabled
#[inline(always)]
pub fn snp_active() -> bool {
    get_cbit_mask() > 0
}

/// Error returned by pvalidate
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Reasons:
    /// - Page size is 2MB and page is not 2MB aligned
    FailInput,
    /// Reasons:
    /// - 2MB validation backed by 4KB pages
    FailSizeMismatch,
    /// Unknown error
    Unknown(u32),
}

/// The size of the page to `pvalidate`
#[repr(u64)]
pub enum PvalidateSize {
    /// A 4k page
    Size4K = 0,
    /// A 2M page
    Size2M = 1,
}

/// AMD pvalidate
///
/// returns `Ok(rmp_changed)` on success with `rmp_changed` indicating if the contents
/// of the RMP entry was changed or not.
///
/// - If `addr` is not a readable mapped page, `pvalidate` will result in a Page Fault, #PF exception.
/// - This is a privileged instruction. Attempted execution at a privilege level other than CPL0 will result in
///   a #GP(0) exception.
/// - VMPL or CPL not zero will result in a #GP(0) exception.
#[inline(always)]
pub fn pvalidate(addr: VirtAddr, size: PvalidateSize, validated: bool) -> Result<bool, Error> {
    let rmp_changed: u32;
    let ret: u64;
    let flag: u32 = if validated { 1 } else { 0 };

    // pvalidate and output the carry bit in edx
    // return value in rax
    unsafe {
        asm!(
        "pvalidate",
        "setc    dl",
        inout("rax") addr.as_u64() & (!0xFFF) => ret,
        in("rcx") size as u64,
        inout("edx") flag => rmp_changed,
        options(nostack, nomem)
        );
    }

    match ret as u32 {
        0 => Ok(rmp_changed as u8 == 0),
        1 => Err(FailInput),
        6 => Err(FailSizeMismatch),
        ret => Err(Unknown(ret)),
    }
}
