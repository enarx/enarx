// SPDX-License-Identifier: Apache-2.0

//! FIXME: add docs

macro_rules! debug {
    ($dst:expr, $($arg:tt)*) => {
        #[allow(unused_must_use)] {
            if $crate::DEBUG {
                use core::fmt::Write;
                write!($dst, $($arg)*);
            }
        }
    };
}

macro_rules! debugln {
    ($dst:expr) => { debugln!($dst,) };
    ($dst:expr, $($arg:tt)*) => {
        #[allow(unused_must_use)] {
            if $crate::DEBUG {
                use core::fmt::Write;
                writeln!($dst, $($arg)*);
            }
        }
    };
}

mod base;
mod enarx;
mod file;
mod memory;
mod other;
mod process;

use core::fmt::Write;
use core::ptr::read_unaligned;

use crate::heap::Heap;
use lset::Line;
use sallyport::syscall::*;
use sallyport::{request, Block};
use sgx::ssa::StateSaveArea;
use x86_64::structures::idt::ExceptionVector;

// Opcode constants, details in Volume 2 of the Intel 64 and IA-32 Architectures Software
// Developer's Manual
const OP_SYSCALL: u16 = 0x050f;
const OP_CPUID: u16 = 0xa20f;

/// Thread local storage for the current thread
pub struct Handler<'a> {
    block: &'a mut Block,
    ssa: &'a mut StateSaveArea,
    heap: Heap,
}

impl<'a> Write for Handler<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if s.as_bytes().is_empty() {
            return Ok(());
        }

        let c = self.new_cursor();
        let (_, untrusted) = c.copy_from_slice(s.as_bytes()).or(Err(core::fmt::Error))?;

        let req = request!(libc::SYS_write => libc::STDERR_FILENO, untrusted, untrusted.len());
        let res = unsafe { self.proxy(req) };

        match res {
            Ok(res) if usize::from(res[0]) > s.bytes().len() => self.attacked(),
            Ok(res) if usize::from(res[0]) == s.bytes().len() => Ok(()),
            _ => Err(core::fmt::Error),
        }
    }
}

impl<'a> Handler<'a> {
    fn new(ssa: &'a mut StateSaveArea, block: &'a mut Block, heap: Line<usize>) -> Self {
        Self {
            ssa,
            block,
            heap: unsafe { Heap::new(heap.into()) },
        }
    }

    /// Finish handling an exception
    pub fn finish(ssa: &'a mut StateSaveArea) {
        if let Some(ExceptionVector::InvalidOpcode) = ssa.vector() {
            if let OP_SYSCALL | OP_CPUID = unsafe { read_unaligned(ssa.gpr.rip as _) } {
                // Skip the instruction.
                ssa.gpr.rip += 2;
                return;
            }
        }

        unsafe { asm!("ud2", options(noreturn)) };
    }

    /// Handle an exception
    pub fn handle(ssa: &'a mut StateSaveArea, block: &'a mut Block, heap: Line<usize>) {
        let mut h = Self::new(ssa, block, heap);

        match h.ssa.vector() {
            Some(ExceptionVector::InvalidOpcode) => {
                match unsafe { read_unaligned(h.ssa.gpr.rip as _) } {
                    OP_SYSCALL => h.handle_syscall(),
                    OP_CPUID => h.handle_cpuid(),
                    r => {
                        debugln!(h, "unsupported opcode: {:?}", r);
                        h.exit(1)
                    }
                }
            }

            _ => h.attacked(),
        }
    }

    fn handle_syscall(&mut self) {
        let ret = self.syscall(
            self.ssa.gpr.rdi.into(),
            self.ssa.gpr.rsi.into(),
            self.ssa.gpr.rdx.into(),
            self.ssa.gpr.r10.into(),
            self.ssa.gpr.r8.into(),
            self.ssa.gpr.r9.into(),
            self.ssa.gpr.rax as usize,
        );

        self.ssa.gpr.rip += 2;

        match ret {
            Err(e) => self.ssa.gpr.rax = -e as u64,
            Ok([rax, rdx]) => {
                self.ssa.gpr.rax = rax.into();
                self.ssa.gpr.rdx = rdx.into();
            }
        }
    }

    fn handle_cpuid(&mut self) {
        debug!(
            self,
            "cpuid({:08x}, {:08x})",
            self.ssa.gpr.rax.clone(),
            self.ssa.gpr.rcx.clone(),
        );

        self.block.msg.req = request!(SYS_ENARX_CPUID => self.ssa.gpr.rax, self.ssa.gpr.rcx);

        unsafe {
            // prevent earlier writes from being moved beyond this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

            asm!("cpuid");

            // prevent later reads from being moved before this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

            self.ssa.gpr.rax = self.block.msg.req.arg[0].into();
            self.ssa.gpr.rbx = self.block.msg.req.arg[1].into();
            self.ssa.gpr.rcx = self.block.msg.req.arg[2].into();
            self.ssa.gpr.rdx = self.block.msg.req.arg[3].into();
        }

        debugln!(
            self,
            " = ({:08x}, {:08x}, {:08x}, {:08x})",
            self.ssa.gpr.rax.clone(),
            self.ssa.gpr.rbx.clone(),
            self.ssa.gpr.rcx.clone(),
            self.ssa.gpr.rdx.clone()
        );

        self.ssa.gpr.rip += 2;
    }
}
