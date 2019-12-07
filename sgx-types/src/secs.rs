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

use super::{attributes::Attributes, miscselect::MiscSelect, xfrm::Xfrm};

/// The SGX Enclave Control Structure (SECS) is a special enclave page that is not
/// visible in the address space. In fact, this structure defines the address
/// range and other global attributes for the enclave and it is the first EPC
/// page created for any enclave. It is moved from a temporary buffer to an EPC
/// by the means of ENCLS(ECREATE) leaf.
///
/// Section 38.7
#[repr(C, align(4096))]
pub struct Secs {
    pub size: u64,           // size of address space (power of 2)
    pub base: u64,           // base address of address space
    pub ssa_frame_size: u32, // size of an SSA frame
    pub miscselect: MiscSelect,
    _reserved1: [u8; 24],
    pub attributes: Attributes,
    pub xfrm: Xfrm,          // XSave-Feature Request Mask (subset of XCR0)
    pub mrenclave: [u8; 32], // SHA256-hash of enclave contents
    _reserved2: [u8; 32],
    pub mrsigner: [u8; 32], // SHA256-hash of pubkey used to sign SIGSTRUCT
    _reserved3: [u8; 32],
    pub config_id: [u8; 64], // user-defined value used in key derivation
    pub isv_prod_id: u16,    // user-defined value used in key derivation
    pub isv_svn: u16,        // user-defined value used in key derivation
    pub config_svn: u16,     // user-defined value used in key derivation
}

testaso! {
    struct Secs: 4096, 4096 => {
        size: 0,
        base: 8,
        ssa_frame_size: 16,
        miscselect: 20,
        attributes: 48,
        xfrm: 56,
        mrenclave: 64,
        mrsigner: 128,
        config_id: 192,
        isv_prod_id: 256,
        isv_svn: 258,
        config_svn: 260
    }
}

/// FIXME: This is not the right way to create this struct. However,
/// I need a little bit more experience working with SECS to know the
/// right way to build the constructor. This works for now.
impl Default for Secs {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// TODO: Implement Secs::new()
