// Copyright 2019 Red Hat, Inc.
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

use super::{attr, isv, misc::MiscSelect, sig::Contents};

/// The SGX Enclave Control Structure (SECS) is a special enclave page that is not
/// visible in the address space. In fact, this structure defines the address
/// range and other global attributes for the enclave and it is the first EPC
/// page created for any enclave. It is moved from a temporary buffer to an EPC
/// by the means of ENCLS(ECREATE) leaf.
///
/// Section 38.7
#[derive(Copy, Clone, Debug)]
#[repr(C, align(4096))]
pub struct Secs {
    pub size: u64,
    pub base: u64,
    pub ssa_size: u32,
    pub misc: MiscSelect,
    reserved0: [u8; 24],
    pub attr: attr::Attributes,
    pub mrenclave: [u8; 32],
    reserved1: [u8; 32],
    pub mrsigner: [u8; 32],
    reserved2: [u64; 12],
    pub isv_prod_id: isv::ProdId,
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
    pub const SIZE_MAX: u64 = 0x1_000_000_000;

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
