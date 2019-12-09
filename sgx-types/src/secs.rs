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

use super::{attr::Attributes, misc::MiscSelect, sig::Signature, utils::Padding};

/// The SGX Enclave Control Structure (SECS) is a special enclave page that is not
/// visible in the address space. In fact, this structure defines the address
/// range and other global attributes for the enclave and it is the first EPC
/// page created for any enclave. It is moved from a temporary buffer to an EPC
/// by the means of ENCLS(ECREATE) leaf.
///
/// Section 38.7
#[repr(C, align(4096))]
pub struct Secs {
    size: u64,           // size of address space (power of 2)
    base: u64,           // base address of address space
    ssa_frame_size: u32, // size of an SSA frame
    misc: MiscSelect,
    reserved1: Padding<[u8; 24]>,
    attr: Attributes,
    mrenclave: [u8; 32], // SHA256-hash of enclave contents
    reserved2: Padding<[u8; 32]>,
    mrsigner: [u8; 32], // SHA256-hash of pubkey used to sign SIGSTRUCT
    reserved3: Padding<[u8; 96]>,
    isv_prod_id: u16, // user-defined value used in key derivation
    isv_svn: u16,     // user-defined value used in key derivation
}

testaso! {
    struct Secs: 4096, 4096 => {
        size: 0,
        base: 8,
        ssa_frame_size: 16,
        misc: 20,
        reserved1: 24,
        attr: 48,
        mrenclave: 64,
        reserved2: 96,
        mrsigner: 128,
        reserved3: 160,
        isv_prod_id: 256,
        isv_svn: 258
    }
}

impl Secs {
    pub fn new(size: u64, base: u64, ssa: u32, sig: &Signature) -> Self {
        Secs {
            size,
            base,
            ssa_frame_size: ssa,
            misc: sig.contents.misc & sig.contents.misc_mask,
            attr: sig.contents.attr & sig.contents.attr_mask,
            mrenclave: sig.contents.mrenclave,
            mrsigner: unsafe { core::mem::zeroed() }, // FIXME
            isv_prod_id: sig.contents.isv_prod_id,
            isv_svn: sig.contents.isv_svn,
            ..unsafe { core::mem::zeroed() }
        }
    }
}
