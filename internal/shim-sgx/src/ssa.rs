// SPDX-License-Identifier: Apache-2.0

use core::mem::size_of;

use primordial::{Page, Register};
use xsave::XSave;

pub use x86_64::structures::idt::ExceptionVector as Vector;

/// Section 38.9.1.1, Table 38-9
#[repr(C, align(4))]
#[derive(Copy, Clone)]
pub struct ExitInfo {
    vector: Vector,
    exit_type: u8,
    reserved: u8,
    valid: u8,
}

impl ExitInfo {
    const VALID: u8 = 1 << 7;

    /// Returns the exception type, if any.
    pub fn exception(self) -> Option<Vector> {
        if self.valid != Self::VALID {
            return None;
        }

        Some(self.vector)
    }
}

/// Section 38.9.1, Table 38-8
#[repr(C)]
pub struct Gpr {
    /// Register rax
    pub rax: Register<u64>,

    /// Register rcx
    pub rcx: Register<u64>,

    /// Register rdx
    pub rdx: Register<u64>,

    /// Register rbx
    pub rbx: Register<u64>,

    /// Register rsp
    pub rsp: Register<u64>,

    /// Register rbp
    pub rbp: Register<u64>,

    /// Register rsi
    pub rsi: Register<u64>,

    /// Register rdi
    pub rdi: Register<u64>,

    /// Register r8
    pub r8: Register<u64>,

    /// Register r9
    pub r9: Register<u64>,

    /// Register r10
    pub r10: Register<u64>,

    /// Register r11
    pub r11: Register<u64>,

    /// Register r12
    pub r12: Register<u64>,

    /// Register r13
    pub r13: Register<u64>,

    /// Register r14
    pub r14: Register<u64>,

    /// Register r15
    pub r15: Register<u64>,

    /// Register flags
    pub rflags: Register<u64>,

    /// Register rip
    pub rip: Register<u64>,

    /// Register ursp
    pub ursp: Register<u64>,

    /// Register urbp
    pub urbp: Register<u64>,

    /// ExitInfo struct
    pub exitinfo: ExitInfo,

    /// Reserved
    pub reserved: u32,

    /// FS base
    pub fsbase: Register<u64>,

    /// GS base
    pub gsbase: Register<u64>,
}

/// Section 38.9.2.1, Table 38-12
#[derive(Debug)]
#[repr(C)]
struct ExceptionInfo {
    /// In case of a page fault, contains the linear address that caused the fault.
    maddr: u64,

    /// Exception error code for GP fault or page fault.
    errcd: u32,

    reserved: u32,
}

/// Section 38.9.2, Table 38-11
#[derive(Debug)]
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

impl StateSaveArea {
    const fn padding() -> usize {
        Page::SIZE - size_of::<XSave>() - size_of::<Miscellaneous>() - size_of::<Gpr>()
    }
}
