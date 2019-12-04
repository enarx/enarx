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

use bitflags::bitflags;

bitflags! {
    /// Section 38.7.1
    pub struct Attributes: u64 {
        const INIT = 1 << 0;
        const DEBUG = 1 << 1;
        const MODE_64_BIT = 1 << 2;
        const PROVISION_KEY = 1 << 4;
        const EINIT_TOKEN_KEY = 1 << 5;
    }
}

bitflags! {
    /// Section 38.7.2
    pub struct MiscSelect: u32 {
        const EXINFO = 1 << 0;
    }
}

bitflags! {
    /// Section 42.7.2.1 and https://en.wikipedia.org/wiki/Control_register
    pub struct Xfrm: u64 {
        const X87 = 1 << 0;       // x87 FPU/MMX State, note, must be '1'
        const SSE = 1 << 1;       // XSAVE feature set enable for MXCSR and XMM regs
        const AVX = 1 << 2;       // AVX enable and XSAVE feature set can be used to manage YMM regs
        const BNDREG = 1 << 3;    // MPX enable and XSAVE feature set can be used for BND regs
        const BNDCSR =  1 << 4;   // PMX enable and XSAVE feature set can be used for BNDCFGU and BNDSTATUS regs
        const OPMASK = 1 << 5;    // AVX-512 enable and XSAVE feature set can be used for AVX opmask, AKA k-mask, regs
        const ZMM_HI256 = 1 << 6; // AVX-512 enable and XSAVE feature set can be used for upper-halves of the lower ZMM regs
        const HI16_ZMM = 1 << 7;  // AVX-512 enable and XSAVE feature set can be used for the upper ZMM regs
        const PKRU = 1 << 9;      // XSAVE feature set can be used for PKRU register (part of protection keys mechanism)
        const CETU = 1 << 11;     // Control-flow Enforcement Technology (CET) user state
        const CETS = 1 << 12;     // Control-flow Enforcement Technology (CET) supervisor state
    }
}

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
    _reserved4: [u8; 3834],
}

/// FIXME: This is not the right way to create this struct. However,
/// I need a little bit more experience working with SECS to know the
/// right way to build the constructor. This works for now.
impl Default for Secs {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// TODO: Implement Secs::new()

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn align() {
        use std::mem::align_of;

        assert_eq!(align_of::<Secs>(), 4096);
    }

    #[test]
    fn size() {
        use std::mem::size_of;

        assert_eq!(size_of::<Secs>(), 4096);
    }
}
