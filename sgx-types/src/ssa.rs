#![allow(clippy::unreadable_literal)]

use crate::utils::Padding;

use core::mem::size_of;

use bitflags::bitflags;

/// Section 38.9.1.1, Table 38-10
#[derive(Copy, Clone, Debug)]
pub enum Exception {
    Divider,
    Debug,
    Breakpoint,
    BoundRange,
    InvalidOpCode,
    GeneralProtection,
    PageFault,
    FloatingPoint,
    AlignmentCheck,
    Simd,
}

/// Section 38.9.1.1, Table 38-9
#[derive(Copy, Clone, Debug)]
pub enum ExitType {
    Hardware,
    Software,
}

/// Section 38.9.1.1, Table 38-9
#[repr(transparent)]
#[derive(Copy, Clone, Default)]
pub struct ExitInfo(u32);

impl core::fmt::Debug for ExitInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let exc = self.exception();
        let et = self.exit_type();

        let status = et.and_then(|et| exc.map(|e| (et, e)));
        write!(f, "ExitInfo({:?})", status)
    }
}

impl ExitInfo {
    pub fn new(et: ExitType, exc: Exception) -> Self {
        let et = match et {
            ExitType::Hardware => 0b011 << 8,
            ExitType::Software => 0b110 << 8,
        };

        let exc = match exc {
            Exception::Divider => 0x00,
            Exception::Debug => 0x01,
            Exception::Breakpoint => 0x03,
            Exception::BoundRange => 0x05,
            Exception::InvalidOpCode => 0x06,
            Exception::GeneralProtection => 0x0d,
            Exception::PageFault => 0x0e,
            Exception::FloatingPoint => 0x10,
            Exception::AlignmentCheck => 0x11,
            Exception::Simd => 0x13,
        };

        ExitInfo(1 << 31 | et | exc)
    }

    pub fn exit_type(self) -> Option<ExitType> {
        const MASK: u32 = 1 << 31 | 0b111 << 8;

        match self.0 & MASK {
            0x80000300 => Some(ExitType::Hardware),
            0x80000600 => Some(ExitType::Software),
            _ => None,
        }
    }

    pub fn exception(self) -> Option<Exception> {
        const MASK: u32 = 1 << 31 | 0xff;

        match self.0 & MASK {
            0x80000000 => Some(Exception::Divider),
            0x80000001 => Some(Exception::Debug),
            0x80000003 => Some(Exception::Breakpoint),
            0x80000005 => Some(Exception::BoundRange),
            0x80000006 => Some(Exception::InvalidOpCode),
            0x8000000d => Some(Exception::GeneralProtection),
            0x8000000e => Some(Exception::PageFault),
            0x80000010 => Some(Exception::FloatingPoint),
            0x80000011 => Some(Exception::AlignmentCheck),
            0x80000013 => Some(Exception::Simd),
            _ => None,
        }
    }
}

/// Section 38.9.1, Table 38-8
#[derive(Debug)]
#[repr(C)]
pub struct Gpr {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
    pub rip: u64,
    pub ursp: u64,
    pub urbp: u64,
    pub exitinfo: ExitInfo,
    pub reserved: u32,
    pub fsbase: u64,
    pub gsbase: u64,
}

bitflags! {
    /// Section 38.9.2.2, Table 38-13
    pub struct PageFault: u32 {
        const P = 1 << 0;
        const WR = 1 << 1;
        const US = 1 << 2;
        const ID = 1 << 4;
        const PK = 1 << 5;
        const SGX = 1 << 5;
    }
}

/// Section 38.9.2.1, Table 38-12
#[derive(Debug)]
#[repr(C)]
pub struct ExceptionInfo {
    maddr: u64,
    errcd: PageFault,
}

/// Section 38.9.2, Table 38-11
#[derive(Debug)]
#[repr(C)]
pub struct Miscellaneous {
    exinfo: ExceptionInfo,
}

// TODO: replace with real XSAVE type
#[derive(Debug)]
#[repr(C, align(4096))]
pub struct XSave(Padding<[u8; 4096]>);

#[derive(Debug)]
#[repr(C, align(4096))]
pub struct Footer {
    padding: Padding<[u8; 4096 - size_of::<Miscellaneous>() - size_of::<Gpr>()]>,
    misc: Miscellaneous,
    gpr: Gpr,
}

/// Section 38.9, Table 38-7
#[derive(Debug)]
#[repr(C)]
pub struct StateSaveArea<T> {
    xsave: XSave,
    other: T,
    footer: Footer,
}

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
        errcd: 8
    }

    struct Miscellaneous: 8, 16 => {
        exinfo: 0
    }

    struct XSave: 4096, 4096 => {
    }

    struct Footer: 4096, 4096 => {
        padding: 0,
        misc: 3896,
        gpr: 3912
    }

    struct StateSaveArea<()>: 4096, 8192 => {
        xsave: 0,
        other: 4096,
        footer: 4096
    }

    struct StateSaveArea<u64>: 4096, 12288 => {
        xsave: 0,
        other: 4096,
        footer: 8192
    }

    struct StateSaveArea<[u8; 4096]>: 4096, 12288 => {
        xsave: 0,
        other: 4096,
        footer: 8192
    }

    struct StateSaveArea<([u8; 4096], u64)>: 4096, 16384 => {
        xsave: 0,
        other: 4096,
        footer: 12288
    }
}
