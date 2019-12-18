bitflags::bitflags! {
    /// Section 38.7.1
    pub struct Flags: u64 {
        const INIT = 1 << 0;
        const DEBUG = 1 << 1;
        const MODE_64_BIT = 1 << 2;
        const PROVISION_KEY = 1 << 4;
        const EINIT_TOKEN_KEY = 1 << 5;
    }
}

defflags!(Flags MODE_64_BIT);

bitflags::bitflags! {
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

defflags!(Xfrm X87 | SSE);

#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Attributes {
    flags: Flags,
    xfrm: Xfrm,
}

impl Attributes {
    pub const fn new(flags: Flags, xfrm: Xfrm) -> Self {
        Self { flags, xfrm }
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
