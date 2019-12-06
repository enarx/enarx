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

impl Default for Xfrm {
    fn default() -> Self {
        Xfrm::X87 | Xfrm::SSE
    }
}
