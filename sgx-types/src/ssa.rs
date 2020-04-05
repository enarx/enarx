// SPDX-License-Identifier: Apache-2.0

//! State Save Area (SSA) Frame (Section 38.9)
//! When an AEX occurs while running in an enclave, the architectural state is saved in the
//! thread’s current SSA frame, which is pointed to by TCS.CSSA.

#![allow(clippy::unreadable_literal)]

use bitflags::bitflags;
use core::{
    mem::{align_of, size_of, MaybeUninit},
    num::NonZeroU32,
};
use enumerate::enumerate;
use intel_types::*;
#[cfg(test)]
use testing::testaso;

enumerate! {
    /// Section 38.9.1.1, Table 38-9
    #[derive(Copy, Clone)]
    pub enum ExitType: u8 {
        /// Hardware
        Hardware = 0b011,

        /// Software
        Software = 0b110,
    }
}

/// Section 38.9.1.1, Table 38-9
#[repr(C, align(4))]
#[derive(Copy, Clone)]
pub struct ExitInfo {
    vector: Exception,
    exit_type: ExitType,
    reserved: u8,
    valid: u8,
}

impl core::fmt::Debug for ExitInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let exc = self.exception();
        let et = self.exit_type();

        let status = et.and_then(|et| exc.map(|e| (et, e)));
        write!(f, "ExitInfo({:?})", status)
    }
}

impl Default for ExitInfo {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl ExitInfo {
    const VALID: u8 = 1 << 7;

    /// Creates ExitInfo based on ExitType and Exception.
    pub fn new(et: ExitType, exc: Exception) -> Self {
        ExitInfo {
            vector: exc,
            exit_type: et,
            reserved: 0,
            valid: Self::VALID,
        }
    }

    /// Returns the exit type, if any.
    pub fn exit_type(self) -> Option<ExitType> {
        if self.valid != Self::VALID {
            return None;
        }

        Some(self.exit_type)
    }

    /// Returns the exception type, if any.
    pub fn exception(self) -> Option<Exception> {
        if self.valid != Self::VALID {
            return None;
        }

        Some(self.vector)
    }
}

/// Section 38.9.1, Table 38-8
#[derive(Debug, Default)]
#[repr(C)]
pub struct Gpr {
    /// Register rax
    pub rax: u64,

    /// Register rcx
    pub rcx: u64,

    /// Register rdx
    pub rdx: u64,

    /// Register rbx
    pub rbx: u64,

    /// Register rsp
    pub rsp: u64,

    /// Register rbp
    pub rbp: u64,

    /// Register rsi
    pub rsi: u64,

    /// Register rdi
    pub rdi: u64,

    /// Register r8
    pub r8: u64,

    /// Register r9
    pub r9: u64,

    /// Register r10
    pub r10: u64,

    /// Register r11
    pub r11: u64,

    /// Register r12
    pub r12: u64,

    /// Register r13
    pub r13: u64,

    /// Register r14
    pub r14: u64,

    /// Register r15
    pub r15: u64,

    /// Register flags
    pub rflags: Rflags,

    /// Register rip
    pub rip: u64,

    /// Register ursp
    pub ursp: u64,

    /// Register urbp
    pub urbp: u64,

    /// ExitInfo struct
    pub exitinfo: ExitInfo,

    /// Reserved
    pub reserved: u32,

    /// FS base
    pub fsbase: u64,

    /// GS base
    pub gsbase: u64,
}

bitflags! {
    /// Flags for a page fault;
    /// Section 38.9.2.2, Table 38-13
    pub struct PageFault: u32 {
        /// Same as non-SGX page fault exception P flag.
        const P = 1 << 0;

        /// Same as non-SGX page fault exception W/R flag.
        const WR = 1 << 1;

        /// Always set to 1 (user mode reference).
        const US = 1 << 2;

        /// Same as non-SGX page fault exception I/D flag.
        const ID = 1 << 4;

        /// Protection Key induced fault.
        const PK = 1 << 5;

        /// EPCM induced fault.
        const SGX = 1 << 15;
    }
}

bitflags! {
    /// Flags for a general protection fault;
    /// The General Protection Fault sets an error code, which is the segment selector index
    /// when the exception is segment related. Otherwise, 0.
    /// For more, refer to: https://wiki.osdev.org/Exceptions
    pub struct GenProtFault: u32 {
        ///  Exception originated externally to the processor.
        const E = 1 << 0;

        /// Bits 1 and 2 together indicate whether the selector (bits 3-15) references a
        /// descriptor in the GDT, IDT, or LDT.
        const TBL1 = 1 << 1;

        /// Bits 1 and 2 together indicate whether the selector (bits 3-15) references a
        /// descriptor in the GDT, IDT, or LDT.
        const TBL2 = 1 << 2;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL3 = 1 << 3;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL4 = 1 << 4;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL5 = 1 << 5;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL6 = 1 << 6;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL7 = 1 << 7;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL8 = 1 << 8;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL9 = 1 << 9;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL10 = 1 << 10;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL11 = 1 << 11;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL12 = 1 << 12;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL13 = 1 << 13;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL14 = 1 << 14;

        /// Selector index (bits 3-15) for the GDT, IDT, or LDT.
        const SEL15 = 1 << 15;
    }
}

/// The `errcd` in ExceptionInfo could be a page fault or a general protection fault.
/// This type represents either.
#[derive(Debug)]
pub enum Fault {
    /// General Protection Fault with flags.
    GP(GenProtFault),

    /// Page Fault with flags and memory address.
    PF(u64, PageFault),
}

/// Section 38.9.2.1, Table 38-12
#[derive(Debug, Default)]
#[repr(C)]
struct ExceptionInfo {
    /// In case of a page fault, contains the linear address that caused the fault.
    maddr: u64,

    /// Exception error code for GP fault or page fault.
    errcd: u32,

    reserved: u32,
}

/// Section 38.9.2, Table 38-11
#[derive(Debug, Default)]
#[repr(C)]
pub struct Miscellaneous {
    /// Exception info for GP or page fault occurring inside an enclave can be written to
    /// this struct under some conditions (see Table 38.11).
    exinfo: ExceptionInfo,
}

/// When an AEX occurs while running in an enclave, the architectural state is saved
/// in the thread’s current StateSaveArea (SSA Frame), which is pointed to by TCS.CSSA.
///
/// Section 38.9, Table 38-7
#[repr(C, align(4096))]
pub struct StateSaveArea {
    /// Area for saving and restoring the XSAVE-managed state components
    pub xsave: XSave,

    /// Padding
    pub reserved: [u8; Self::padding()],

    /// Contains Exception Info (error condition, memory address)
    pub misc: Miscellaneous,

    /// Contains Exit Info (exit and exception type)
    pub gpr: Gpr,
}

impl Default for StateSaveArea {
    fn default() -> Self {
        Self {
            xsave: Default::default(),
            reserved: [0u8; Self::padding()],
            misc: Default::default(),
            gpr: Default::default(),
        }
    }
}

impl StateSaveArea {
    /// Converts an internal fault type to a safe Rust enum describing the fault.
    pub fn fault(&self) -> Option<Fault> {
        self.gpr.exitinfo.exit_type()?;
        match self.gpr.exitinfo.exception() {
            Some(Exception::Page) => Some(Fault::PF(
                self.misc.exinfo.maddr,
                PageFault::from_bits(self.misc.exinfo.errcd).unwrap(),
            )),
            Some(Exception::GeneralProtection) => Some(Fault::GP(
                GenProtFault::from_bits(self.misc.exinfo.errcd).unwrap(),
            )),
            _ => None,
        }
    }

    const fn padding() -> usize {
        #[repr(C, align(4096))]
        struct Unpadded(XSave, Miscellaneous, Gpr);

        size_of::<Unpadded>() - size_of::<XSave>() - size_of::<Miscellaneous>() - size_of::<Gpr>()
    }

    /// Returns the size of the SSA in 4k pages, rather than bytes. According to
    /// the documentation, SSAFrameSize (used in SECS) is referenced in pages.
    /// See section 38.7 for page-size requirement for SECS and Table 38-7 for
    /// requirement that the SSA is page aligned.
    pub const fn frame_size() -> NonZeroU32 {
        let pages = size_of::<StateSaveArea>() / align_of::<StateSaveArea>();
        unsafe { NonZeroU32::new_unchecked(pages as u32) }
    }
}

#[cfg(test)]
testaso! {
    struct Gpr: 8, 184 => {
        rax: 0,
        rcx: 8,
        rdx: 16,
        rbx: 24,
        rsp: 32,
        rbp: 40,
        rsi: 48,
        rdi: 56,
        r8: 64,
        r9: 72,
        r10: 80,
        r11: 88,
        r12: 96,
        r13: 104,
        r14: 112,
        r15: 120,
        rflags: 128,
        rip: 136,
        ursp: 144,
        urbp: 152,
        exitinfo: 160,
        reserved: 164,
        fsbase: 168,
        gsbase: 176
    }

    struct ExceptionInfo: 8, 16 => {
        maddr: 0,
        errcd: 8,
        reserved: 12
    }

    struct Miscellaneous: 8, 16 => {
        exinfo: 0
    }

    struct StateSaveArea: 4096, 4096 => {
        xsave: 0,
        reserved: 576,
        misc: 3896,
        gpr: 3912
    }
}
