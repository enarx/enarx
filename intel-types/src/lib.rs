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
