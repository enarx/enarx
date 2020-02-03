// Copyright 2020 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! SECS (Section 38.7)
//! The SGX Enclave Control Structure (SECS) is a special enclave page that is not
//! visible in the address space. In fact, this structure defines the address
//! range and other global attributes for the enclave and it is the first EPC
//! page created for any enclave. It is moved from a temporary buffer to an EPC
//! by the means of ENCLS(ECREATE) leaf.

use super::{attr, isv, misc::MiscSelect, sig::Contents};
use core::num::{NonZeroU32, NonZeroU64};

/// An enclave's size specification
pub struct Spec {
    /// The enclave size (in bytes; power of 2)
    pub enc_size: NonZeroU64,

    /// The state save area frame size (in bytes)
    pub ssa_size: NonZeroU32,
}

impl Spec {
    /// # Usage
    /// Returns the maximum enclave size for 64bit in bytes.
    /// CPUID.(EAX=12H, ECX=0H) enumerates Intel SGX capability;
    /// For more on CPUID enumeration leaves, see 37.7.2 and Table 37-4.
    ///
    /// # Safety
    /// This function is unsafe because it does not check if the `CPUID` instruction
    /// is available before issuing it.
    pub unsafe fn max_enc_size() -> Option<NonZeroU64> {
        const LEAF_MAX_PARAM: u32 = 0x0;
        const LEAF_SGX_SUPPORT: u32 = 0x07;
        const SUBLEAF_SGX_SUPPORT: u32 = 0x0;
        const LEAF_MAX_ENCL_SIZE: u32 = 0x12;
        const SUBLEAF_MAX_ENCL_SIZE: u32 = 0x0;

        // Test for max leaf size
        let res = core::arch::x86_64::__get_cpuid_max(LEAF_MAX_PARAM);
        let max_leaf = res.0;
        if max_leaf < LEAF_SGX_SUPPORT || max_leaf < LEAF_MAX_ENCL_SIZE {
            return None;
        }

        // Test for SGX support
        let res = core::arch::x86_64::__cpuid_count(LEAF_SGX_SUPPORT, SUBLEAF_SGX_SUPPORT);
        if res.ebx & (1 << 2) == 0 {
            return None;
        }

        // Test for max enclave size
        let res = core::arch::x86_64::__cpuid_count(LEAF_MAX_ENCL_SIZE, SUBLEAF_MAX_ENCL_SIZE);
        let max_size: u64 = 1 << (res.edx >> 8 as u8) as u64;
        Some(NonZeroU64::new(max_size).unwrap())
    }
}

/// Section 38.7
#[derive(Copy, Clone, Debug)]
#[repr(C, align(4096))]
pub struct Secs {
    enc_size: NonZeroU64,
    enc_base: u64,
    ssa_size: NonZeroU32,
    misc: MiscSelect,
    reserved0: [u8; 24],
    attr: attr::Attributes,
    mrenclave: [u8; 32],
    reserved1: [u8; 32],
    mrsigner: [u8; 32],
    reserved2: [u64; 12],
    isv_prod_id: isv::ProdId,
    isv_svn: isv::Svn,
}

testaso! {
    struct Secs: 4096, 4096 => {
        enc_size: 0,
        enc_base: 8,
        ssa_size: 16,
        misc: 20,
        reserved0: 24,
        attr: 48,
        mrenclave: 64,
        reserved1: 96,
        mrsigner: 128,
        reserved2: 160,
        isv_prod_id: 256,
        isv_svn: 258
    }
}

impl Secs {
    /// Creates a new SECS struct based on a base address, size, SSA size, and Contents.
    pub fn new(base: u64, spec: Spec, mrsigner: [u8; 32], contents: &Contents) -> Self {
        Self {
            enc_size: spec.enc_size,
            enc_base: base,
            ssa_size: spec.ssa_size,
            misc: contents.misc.data & contents.misc.mask,
            reserved0: [0; 24],
            attr: contents.attr.data & contents.attr.mask,
            mrenclave: contents.mrenclave,
            reserved1: [0; 32],
            mrsigner,
            reserved2: [0; 12],
            isv_prod_id: contents.isv_prod_id,
            isv_svn: contents.isv_svn,
        }
    }
}
