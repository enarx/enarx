// SPDX-License-Identifier: Apache-2.0

//! Intel Documentation related to these types is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf

#![cfg_attr(not(test), no_std)]
#![deny(clippy::all)]
#![allow(clippy::identity_op)]
#![deny(missing_docs)]

use bitflags::bitflags;
use core::{
    fmt::Debug,
    ops::{BitAnd, BitOr, Not},
};
#[cfg(test)]
use testing::testaso;

/// Succinctly describes a masked type, e.g. masked Attributes or masked MiscSelect.
/// A mask is applied to Attributes and MiscSelect structs in a Signature (SIGSTRUCT)
/// to specify values of Attributes and MiscSelect to enforce. This struct combines
/// the struct and its mask for simplicity.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Masked<T: BitAnd<Output = T>> {
    /// The data being masked, e.g. Attribute flags.
    pub data: T,

    /// The mask.
    pub mask: T,
}

impl<T> Default for Masked<T>
where
    T: BitAnd<Output = T>,
    T: BitOr<Output = T>,
    T: Not<Output = T>,
    T: Default,
    T: Copy,
{
    fn default() -> Self {
        T::default().into()
    }
}

impl<T> From<T> for Masked<T>
where
    T: BitAnd<Output = T>,
    T: BitOr<Output = T>,
    T: Not<Output = T>,
    T: Copy,
{
    fn from(value: T) -> Self {
        Self {
            data: value,
            mask: value | !value,
        }
    }
}

impl<T> PartialEq<T> for Masked<T>
where
    T: BitAnd<Output = T>,
    T: PartialEq,
    T: Copy,
{
    fn eq(&self, other: &T) -> bool {
        self.mask & self.data == self.mask & *other
    }
}

enumerate::enumerate! {
    /// Exception Error Codes
    #[derive(Copy, Clone)]
    pub enum Exception: u8 {
        /// Divide-by-zero Error
        DivideByZero = 0x00,

        /// Debug
        Debug = 0x01,

        /// Breakpoint
        Breakpoint = 0x03,

        /// Overflow
        Overflow = 0x04,

        /// Bound Range Exceeded
        BoundRange = 0x05,

        /// Invalid Opcode
        InvalidOpcode = 0x06,

        /// Device Not Available
        DeviceNotAvailable = 0x07,

        /// Double Fault
        DoubleFault = 0x08,

        /// Invalid TSS
        InvalidTss = 0x0A,

        /// Segment Not Present
        SegmentNotPresent = 0x0B,

        /// Stack-Segment Fault
        StackSegment = 0x0C,

        /// General Protection Fault
        GeneralProtection = 0x0D,

        /// Page Fault
        Page = 0x0E,

        /// x87 Floating-Point Exception
        FloatingPoint = 0x10,

        /// Alignment Check
        AlignmentCheck = 0x11,

        /// Machine Check
        MachineCheck = 0x12,

        /// SIMD Floating-Point Exception
        SimdFloatingPoint = 0x13,

        /// Virtualization Exception
        Virtualization = 0x14,

        /// Control Protection Exception
        ControlProtection = 0x15,

        /// Security Exception
        Security = 0x1E,
    }
}

/// This type represents an MMX register, used to perform operations on 64-bit packed integer data.
/// It includes the 10-byte value as well as 6 bytes of padding.
#[derive(Debug, Default)]
#[repr(C)]
pub struct Mm([u8; 16]);

/// This type represents an XMM 128-bit data register, used to operate on packed single-
/// precision floating-point operands.
#[derive(Debug, Default)]
#[repr(C)]
pub struct Xmm([u8; 16]);

bitflags! {
    /// x87 Floating Point Unit (FPU) Control Word
    /// Section 8.1.5
    #[repr(transparent)]
    pub struct Fcw: u16 {
        /// Invalid Operation
        const INV_OP = 1 << 0;

        /// Denormal Operand
        const DENORM_OP = 1 << 1;

        /// Zero Divide
        const ZERO_DIV = 1 << 2;

        /// Overflow
        const OVERFLOW = 1 << 3;

        /// Underflow
        const UNDERFLOW = 1 << 4;

        /// Precision
        const PREC = 1 << 5;

        /// Precision Control 0
        const PREC_CTRL0 = 1 << 8;

        /// Precision Control 1
        const PREC_CTRL1 = 1 << 9;

        /// Rounding Control 0
        const ROUND_CTRL0 = 1 << 10;

        /// Rounding Control 1
        const ROUND_CTRL1 = 1 << 11;

        /// Infinity Control
        const INFINITY_CTRL = 1 << 12;
    }
}

impl Default for Fcw {
    /// The x87 state initial configuration for FCW masks all floating-point exceptions,
    /// sets rounding to nearest, and sets the x87 FPU precision to 64 bits.
    /// See Section 8.1.5.
    fn default() -> Self {
        Fcw::INV_OP
            | Fcw::DENORM_OP
            | Fcw::ZERO_DIV
            | Fcw::OVERFLOW
            | Fcw::UNDERFLOW
            | Fcw::PREC
            | Fcw::PREC_CTRL0
            | Fcw::PREC_CTRL1
    }
}

bitflags! {
    /// 32-bit register providing status and control bits used in SIMD floating-point operations
    #[repr(transparent)]
    pub struct MxCsr: u32 {
        /// Invalid Operation Flag
        const INV_OP = 1 << 0;

        /// Denormal Flag
        const DENORM = 1 << 1;

        /// Divide by Zero Flag
        const ZERO_DIV = 1 << 2;

        /// Overflow Flag
        const OVERFLOW = 1 << 3;

        /// Underflow Flag
        const UNDERFLOW = 1 << 4;

        /// Precision Flag
        const PREC = 1 << 5;

        /// Denormals are Zeros
        const DENORM_ARE_ZEROS = 1 << 6;

        /// Invalid Operation Mask
        const INV_OP_MASK = 1 << 7;

        /// Denormal Operation Mask
        const DENORM_MASK = 1 << 8;

        /// Divide by Zero Mask
        const ZERO_DIV_MASK = 1 << 9;

        /// Overflow Mask
        const OVERFLOW_MASK = 1 << 10;

        /// Underflow Mask
        const UNDERFLOW_MASK = 1 << 11;

        /// Precision Mask
        const PREC_MASK = 1 << 12;

        /// Rounding Control 0
        const ROUND_CTRL0 = 1 << 13;

        /// Rounding Control 1
        const ROUND_CTRL1 = 1 << 14;

        /// Flush to Zero
        const FLUSH_TO_ZERO = 1 << 15;
    }
}

impl Default for MxCsr {
    /// The initial state of MXCSR after power-up/reset or INIT; mask allows software
    /// to identify any reserved bits in MXCSR (none are reserved here).
    /// See Sections 11.6.4 and 11.6.6.
    fn default() -> Self {
        MxCsr::INV_OP_MASK
            | MxCsr::DENORM_MASK
            | MxCsr::ZERO_DIV_MASK
            | MxCsr::OVERFLOW_MASK
            | MxCsr::UNDERFLOW_MASK
            | MxCsr::PREC_MASK
    }
}

bitflags! {
    /// Section 13.4.3
    #[repr(transparent)]
    pub struct XcompBv: u64 {
        /// Compacted form is used for the layout of the XSAVE EXtended Region
        const COMPACT = 1 << 63;
    }
}

impl Default for XcompBv {
    /// XCOMP_BV[63] = 1, compaction mode for the XSave Extended Region. However, no state
    /// components are included in the Extended Region as all other bits are 0. The size of
    /// the XSaveXtd is therefore zero.
    // TODO: Check this value, as the original appears to set bit 31 but claims to set bit 63
    fn default() -> Self {
        XcompBv::COMPACT
    }
}

bitflags! {
    /// The state component bitmap identifies the state components present in the XSAVE area.
    /// Bits 62:10 are reserved. Bit 63 does not correspond to any state component.
    /// Section 13.1
    #[derive(Default)]
    #[repr(transparent)]
    pub struct XstateBv: u64 {
        /// x87 state (Section 13.5.1)
        const X87 = 1 << 0;

        /// SSE state (Section 13.5.2)
        const SSE = 1 << 1;

        /// AVX state (Section 13.5.3)
        const AVX = 1 << 2;

        /// MPX state: BND0-BND3 (BNDREGS state)
        const BNDREGS = 1 << 3;

        /// MPX state: BNDCFGU and BNDSTATUS (BNDCSR state)
        const BNDCSR  = 1 << 4;

        /// AVX-512 state: opmask state
        const AVX512_OPMASK = 1 << 5;

        /// AVX-512 state: ZMM_HI256 state
        const AVX512_ZMM_HI256 = 1 << 6;

        /// AVX-512 state: HI16_ZMM state
        const AVX512_HI16_ZMM = 1 << 7;

        /// Processor Trace MSRs
        const PT = 1 << 8;

        /// Protection key feature register (Section 13.5.7)
        const PKRU = 1 << 9;
    }
}

/// The legacy region of an XSAVE area comprises the 512 bytes starting at the area's base address.
/// See Table 13-1. There is no alignment requirement.
#[derive(Debug, Default)]
#[repr(C)]
pub struct XSaveLegacy {
    /// x87 Floating Point Unit (FPU) Control Word
    pub fcw: Fcw,

    /// x87 FPU Status Word
    pub fsw: u16,

    /// x87 FPU Tag Word
    pub ftw: u8,

    /// Reserved
    pub reserved0: u8,

    /// x87 FPU Opcode
    pub fop: u16,

    /// x87 FPU Instruction Pointer Offset
    pub fip: u64,

    /// x87 FPU Data Pointer Offset
    pub fdp: u64,

    /// 32-bit register providing status and control bits used in SIMD floating-point operations
    pub mxcsr: Masked<MxCsr>,

    /// Register used to perform operations on 64-bit packed integer data
    pub mm: [Mm; 8],

    /// 128-bit data register used to operate on packed single-precision floating-point operands
    pub xmm: [Xmm; 16],

    /// Padding: Size of XSaveLegacy must be 512.
    pub padding0: [u64; 11],

    /// Padding: Size of XSaveLegacy must be 512.
    pub padding1: [u8; 7],
}

/// The XSAVE header of an XSAVE area comprises the 64 bytes starting at offset 512 from the
/// area's base address. See Section 13.4.2. There is no alignment requirement.
#[derive(Debug, Default)]
#[repr(C)]
pub struct XSaveHeader {
    /// State-component bitmap identifying the state components in the XSAVE area.
    pub xstate_bv: XstateBv,

    /// State-component bitmap indicating the format of the XSAVE extended region and whether
    /// a component is in the XSAVE area.
    pub xcomp_bv: XcompBv,

    /// Reserved
    pub reserved0: [u64; 6],
}

/// For our use case, the XSave Extended Region is in compacted format and currently holds nothing,
/// as specifed in XCOMP_BV in
/// https://github.com/jsakkine-intel/linux-sgx/blob/master/tools/testing/selftests/x86/sgx/encl_bootstrap.S#L89.
/// For more on this region, see Section 13.4.3. The alignment requirements are variable and specified in
/// 13.4.3.
#[derive(Debug, Default)]
#[repr(C)]
pub struct XSaveExtend([u8; 0]);

/// For details on the fields included in XSave, see Section 13.4. Must be 64 byte aligned.
#[derive(Debug, Default)]
#[repr(C, align(64))]
pub struct XSave {
    /// Legacy region of the XSave area
    pub legacy: XSaveLegacy,

    /// XSave header
    pub header: XSaveHeader,

    /// XSave Extended Region (not used)
    pub extend: XSaveExtend,
}

bitflags! {
    /// In 64-bit mode, EFLAGS is extended to 64 bits and called RFLAGS.
    /// The upper 32 bits of RFLAGS register is reserved. The lower 32 bits
    /// of RFLAGS is the same as EFLAGS.
    /// S prefix indicates a status flag; C indicates a control flag; X
    /// indicates a system flag.
    ///
    /// See Section 3.4.3.4, 3.4.3, and Figure 3-8.
    #[derive(Default)]
    #[repr(transparent)]
    pub struct Rflags: u64 {
        /// Carry flag
        const S_CF = 1 << 0;

        /// Parity flag
        const S_PF = 1 << 2;

        /// Auxiliary Carry Flag
        const S_AF = 1 << 4;

        /// Zero flag
        const S_ZF = 1 << 6;

        /// Sign flag
        const S_SF = 1 << 7;

        /// Trap flag
        const X_TF = 1 << 8;

        /// Interrupt enable flag
        const X_IF = 1 << 9;

        /// Direction flag
        const C_DF = 1 << 10;

        /// Overflow flag
        const S_OF = 1 << 11;

        /// I/O privilege level
        const X_IOPL0 = 1 << 12;

        /// I/O privilege level
        const X_IOPL1 = 1 << 13;

        /// Nested task
        const X_NT = 1 << 14;

        /// Resume flag
        const X_RF = 1 << 16;

        /// Virtual-8086 mode
        const X_VM = 1 << 17;

        /// Alignment check / access control
        const X_AC = 1 << 18;

        /// Virtual interrupt flag
        const X_VIF = 1 << 19;

        /// Virtual interrupt pending
        const X_VIP = 1 << 20;

        /// ID flag (ID)
        const X_ID = 1 << 21;
    }
}

#[cfg(test)]
testaso! {
    struct XSaveLegacy: 8, 512 => {
        fcw: 0,
        fsw: 2,
        ftw: 4,
        reserved0: 5,
        fop: 6,
        fip: 8,
        fdp: 16,
        mxcsr: 24,
        mm: 32,
        xmm: 160,
        padding0: 416,
        padding1: 504
    }

    struct XSaveHeader: 8, 64 => {
        xstate_bv: 0,
        xcomp_bv: 8,
        reserved0: 16
    }

    struct XSaveExtend: 1, 0 => { }

    struct XSave: 64, 576 => {
        legacy: 0,
        header: 512,
        extend: 576
    }
}
