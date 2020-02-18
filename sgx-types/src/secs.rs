// SPDX-License-Identifier: Apache-2.0

//! SECS (Section 38.7)
//! The SGX Enclave Control Structure (SECS) is a special enclave page that is not
//! visible in the address space. In fact, this structure defines the address
//! range and other global attributes for the enclave and it is the first EPC
//! page created for any enclave. It is moved from a temporary buffer to an EPC
//! by the means of ENCLS(ECREATE) leaf.

use super::{attr, isv, misc::MiscSelect};
use core::num::{NonZeroU32, NonZeroUsize};
use testing::testaso;

/// Section 38.7
#[derive(Copy, Clone, Debug)]
#[repr(C, align(4096))]
pub struct Secs {
    size: u64,
    baseaddr: u64,
    ssaframesize: NonZeroU32,
    miscselect: MiscSelect,
    reserved0: [u8; 24],
    attributes: attr::Attributes,
    mrenclave: [u8; 32],
    reserved1: [u8; 32],
    mrsigner: [u8; 32],
    reserved2: [u64; 12],
    isvprodid: isv::ProdId,
    isvsvn: isv::Svn,
    reserved3: [u32; 7],
    reserved4: [[u64; 28]; 17],
}

testaso! {
    struct Secs: 4096, 4096 => {
        size: 0,
        baseaddr: 8,
        ssaframesize: 16,
        miscselect: 20,
        reserved0: 24,
        attributes: 48,
        mrenclave: 64,
        reserved1: 96,
        mrsigner: 128,
        reserved2: 160,
        isvprodid: 256,
        isvsvn: 258,
        reserved3: 260,
        reserved4: 288
    }
}

impl Secs {
    /// Creates a new SECS struct based on a base address and spec.
    pub fn new(base: usize, size: usize, ssa_pages: NonZeroU32) -> Self {
        Self {
            size: size as _,
            baseaddr: base as _,
            ssaframesize: ssa_pages,
            miscselect: MiscSelect::default(),
            reserved0: [0; 24],
            attributes: attr::Attributes::default(),
            mrenclave: [0; 32],
            reserved1: [0; 32],
            mrsigner: [0; 32],
            reserved2: [0; 12],
            isvprodid: isv::ProdId::default(),
            isvsvn: isv::Svn::default(),
            reserved3: [0; 7],
            reserved4: [[0; 28]; 17],
        }
    }

    /// # Usage
    /// Returns the maximum enclave size for 64bit in bytes.
    /// CPUID.(EAX=12H, ECX=0H) enumerates Intel SGX capability;
    /// For more on CPUID enumeration leaves, see 37.7.2 and Table 37-4.
    ///
    /// # Safety
    /// This function is technically unsafe because it does not check if the
    /// `CPUID` instruction is available before issuing it. This could result
    /// in a crash on some very old CPUs. However, the only modern context
    /// where it could crash is environments like SGX or some virtualized
    /// CPUs. But even in these contexts, it is common to trap and emulate the
    /// instruction.
    ///
    /// Therefore, it is common practice to ignore the test to see if the
    /// `CPUID` instruction is available and just issue it anyway. For this
    /// reason, we are marking this function as safe. For more background to
    /// the state of `CPUID` in Rust, see:
    ///
    /// https://github.com/rust-lang/rust/issues/60123
    ///
    pub fn max_enc_size() -> Option<NonZeroUsize> {
        use core::arch::x86_64::{__cpuid_count, __get_cpuid_max};

        const LEAF_MAX_PARAM: u32 = 0x0;
        const LEAF_SGX_SUPPORT: u32 = 0x07;
        const SUBLEAF_SGX_SUPPORT: u32 = 0x0;
        const LEAF_MAX_ENCL_SIZE: u32 = 0x12;
        const SUBLEAF_MAX_ENCL_SIZE: u32 = 0x0;

        // Test for max leaf size
        let res = unsafe { __get_cpuid_max(LEAF_MAX_PARAM) };
        let max_leaf = res.0;
        if max_leaf < LEAF_SGX_SUPPORT || max_leaf < LEAF_MAX_ENCL_SIZE {
            return None;
        }

        // Test for SGX support
        let res = unsafe { __cpuid_count(LEAF_SGX_SUPPORT, SUBLEAF_SGX_SUPPORT) };
        if res.ebx & (1 << 2) == 0 {
            return None;
        }

        // Test for max enclave size
        let res = unsafe { __cpuid_count(LEAF_MAX_ENCL_SIZE, SUBLEAF_MAX_ENCL_SIZE) };
        let max_size: u64 = 1 << (res.edx >> 8 as u8) as u64;

        NonZeroUsize::new(max_size as usize)
    }
}
