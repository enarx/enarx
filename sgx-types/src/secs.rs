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

/// Section 38.7
#[derive(Copy, Clone, Debug)]
#[repr(C, align(4096))]
pub struct Secs {
    /// Size of address space (power of 2).
    pub size: u64,
    /// Base address of address space.
    pub base: u64,
    /// Size of an SSA frame.
    pub ssa_size: u32,
    /// Enumerates info the processor can save into the MISC region of SSA when an AEX occurs.
    pub misc: MiscSelect,
    reserved0: [u8; 24],
    /// Enclave attributes as described in Table 38-3.
    pub attr: attr::Attributes,
    /// SHA256 hash of enclave contents.
    pub mrenclave: [u8; 32],
    reserved1: [u8; 32],
    /// SHA256 hash of pubkey used to sign SIGSTRUCT.
    pub mrsigner: [u8; 32],
    reserved2: [u64; 12],
    /// User-defined value used in key derivation.
    pub isv_prod_id: isv::ProdId,
    /// User-defined value used in key derivation.
    pub isv_svn: isv::Svn,
}

testaso! {
    struct Secs: 4096, 4096 => {
        size: 0,
        base: 8,
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
    /// TODO: The max size of an enclave should come from CPUID, which is inaccessible from within SGX.
    pub const SIZE_MAX: u64 = 0x1_000_000_000;

    /// Creates a new SECS struct based on a base address, size, SSA size, and Contents.
    pub fn new(base: u64, size: u64, ssa: u32, mrsigner: [u8; 32], contents: &Contents) -> Self {
        Self {
            size,
            base,
            ssa_size: ssa,
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
