// SPDX-License-Identifier: Apache-2.0

//! SNP specific modules and functions

use core::arch::asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::VirtAddr;

pub use cpuid_page::{cpuid, cpuid_count, get_cpuid_max};

pub mod attestation;
pub mod cpuid_page;
pub mod ghcb;
pub mod launch;
pub mod secrets_page;
pub mod vmsa;

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
pub enum PvalidateError {
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
#[cfg_attr(coverage, no_coverage)]
pub fn pvalidate(
    addr: VirtAddr,
    size: PvalidateSize,
    validated: bool,
) -> Result<bool, PvalidateError> {
    let rmp_changed: u32;
    let ret: u64;
    let flag: u32 = validated.into();

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
        1 => Err(PvalidateError::FailInput),
        6 => Err(PvalidateError::FailSizeMismatch),
        ret => Err(PvalidateError::Unknown(ret)),
    }
}

/// Error returned by rmpadjust
#[derive(Debug)]
#[non_exhaustive]
pub enum RmpadjustError {
    /// Reasons:
    /// - Page size is 2MB and page is not 2MB aligned
    FailInput,
    /// Reasons:
    /// - Insufficient permissions
    FailPermission,
    /// Reasons:
    /// - 2MB validation backed by 4KB pages
    FailSizeMismatch,
    /// Unknown error
    Unknown(u32),
}

/// The size of the page to `rmpadjust`
#[repr(u64)]
pub enum RmpadjustSize {
    /// A 4k page
    Size4K = 0,
}

const RMPADJUST_VMSA_PAGE_BIT: u64 = 1 << 16;

/// AMD rmpadjust
///
/// returns `Ok(())` on success
///
/// - If `addr` is not a readable mapped page, `rmpadjust` will result in a Page Fault, #PF exception.
/// - This is a privileged instruction. Attempted execution at a privilege level other than CPL0 will result in
///   a #GP(0) exception.
/// - VMPL or CPL not zero will result in a #GP(0) exception.
#[inline(always)]
#[cfg_attr(coverage, no_coverage)]
pub fn rmpadjust(addr: VirtAddr, size: RmpadjustSize, attrs: u64) -> Result<(), RmpadjustError> {
    let ret: u64;

    // pvalidate and output the carry bit in edx
    // return value in rax
    unsafe {
        asm!(
        "rmpadjust",
        inout("rax") addr.as_u64() & (!0xFFF) => ret,
        in("rcx") size as u64,
        in("rdx") attrs,
        options(nostack, nomem)
        );
    }

    match ret as u32 {
        0 => Ok(()),
        1 => Err(RmpadjustError::FailInput),
        2 => Err(RmpadjustError::FailPermission),
        6 => Err(RmpadjustError::FailSizeMismatch),
        ret => Err(RmpadjustError::Unknown(ret)),
    }
}

/// A trait for types that can be serialized and deserialized to/from a byte slice.
///
/// # Safety
///
/// Behavior is undefined if Self is initialized with bytes, which do not represent a valid state.
pub unsafe trait ByteSized: Sized {
    /// The constant default value.
    const SIZE: usize = size_of::<Self>();

    /// Create Self from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }

        Some(unsafe { (bytes.as_ptr() as *const _ as *const Self).read_unaligned() })
    }

    /// Serialize Self to a byte slice.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: This is safe because we know that the pointer is non-null and the length is correct
        // and u8 does not need any alignment.
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, Self::SIZE) }
    }
}
