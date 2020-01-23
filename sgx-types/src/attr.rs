// SPDX-License-Identifier: Apache-2.0

//! Attributes (Section 38.7.1)
//! The attributes of an enclave are specified by the struct below as described.

bitflags::bitflags! {
    /// Section 38.7.1.
    pub struct Flags: u64 {
        /// Enclave has been initialized by EINIT.
        const INIT = 1 << 0;
        /// Perm for debugger to r/w enclave data with EDBGRD and EDBGWR.
        const DEBUG = 1 << 1;
        /// Enclave runs in 64-bit mode.
        const BIT64 = 1 << 2;
        /// Provisioning Key is available from EGETKEY.
        const PROV_KEY = 1 << 4;
        /// EINIT token key is available from EGETKEY.
        const EINIT_KEY = 1 << 5;
    }
}

defflags!(Flags BIT64);

bitflags::bitflags! {
    /// Section 42.7.2.1; more info can be found at https://en.wikipedia.org/wiki/Control_register.
    pub struct Xfrm: u64 {
        /// x87 FPU/MMX State, note, must be '1'.
        const X87 = 1 << 0;
        /// XSAVE feature set enable for MXCSR and XMM regs.
        const SSE = 1 << 1;
        /// AVX enable and XSAVE feature set can be used to manage YMM regs.
        const AVX = 1 << 2;
        /// MPX enable and XSAVE feature set can be used for BND regs.
        const BNDREG = 1 << 3;
        /// PMX enable and XSAVE feature set can be used for BNDCFGU and BNDSTATUS regs.
        const BNDCSR =  1 << 4;
        /// AVX-512 enable and XSAVE feature set can be used for AVX opmask, AKA k-mask, regs.
        const OPMASK = 1 << 5;
        /// AVX-512 enable and XSAVE feature set can be used for upper-halves of the lower ZMM regs.
        const ZMM_HI256 = 1 << 6;
        /// AVX-512 enable and XSAVE feature set can be used for the upper ZMM regs.
        const HI16_ZMM = 1 << 7;
        /// XSAVE feature set can be used for PKRU register (part of protection keys mechanism).
        const PKRU = 1 << 9;
        /// Control-flow Enforcement Technology (CET) user state.
        const CETU = 1 << 11;
        /// Control-flow Enforcement Technology (CET) supervisor state.
        const CETS = 1 << 12;
    }
}

defflags!(Xfrm X87 | SSE);

#[repr(C, packed(4))]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
/// Section 38.7.1.
pub struct Attributes {
    flags: Flags,
    xfrm: Xfrm,
}

impl Attributes {
    /// Creates new Attributes struct from Flags and Xfrm.
    pub const fn new(flags: Flags, xfrm: Xfrm) -> Self {
        Self { flags, xfrm }
    }

    /// Returns flags value of Attributes.
    pub const fn flags(&self) -> Flags {
        self.flags
    }

    /// Returns xfrm value of Attributes.
    pub const fn xfrm(&self) -> Xfrm {
        self.xfrm
    }
}

impl core::ops::BitAnd for Attributes {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Attributes {
            flags: self.flags & other.flags,
            xfrm: self.xfrm & other.xfrm,
        }
    }
}

testaso! {
    struct Attributes: 4, 16 => {}
}
