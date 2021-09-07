// SPDX-License-Identifier: Apache-2.0

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

use enarx_heap::Heap;
use lset::Line;
use sallyport::syscall::*;
use sallyport::{request, Block};
use sgx::types::ssa::{Exception, Gpr};

// Opcode constants, details in Volume 2 of the Intel 64 and IA-32 Architectures Software
// Developer's Manual
const OP_SYSCALL: &[u8] = &[0x0f, 0x05];
const OP_CPUID: &[u8] = &[0x0f, 0xa2];

pub struct Handler<'a> {
    block: &'a mut Block,
    gpr: &'a mut Gpr,
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
    fn new(gpr: &'a mut Gpr, block: &'a mut Block, heap: Line<usize>) -> Self {
        Self {
            gpr,
            block,
            heap: unsafe { Heap::new(heap.into()) },
        }
    }

    /// Finish handling an exception
    pub fn finish(gpr: &'a mut Gpr) {
        if let Some(Exception::InvalidOpcode) = gpr.exitinfo.exception() {
            if let OP_SYSCALL | OP_CPUID = unsafe { gpr.rip.into_slice(2usize) } {
                // Skip the instruction.
                let rip = usize::from(gpr.rip);
                gpr.rip = (rip + 2).into();
                return;
            }
        }

        unsafe { asm!("ud2", options(noreturn)) };
    }

    /// Handle an exception
    pub fn handle(gpr: &'a mut Gpr, block: &'a mut Block, heap: Line<usize>) {
        let mut h = Self::new(gpr, block, heap);

        match h.gpr.exitinfo.exception() {
            Some(Exception::InvalidOpcode) => match unsafe { h.gpr.rip.into_slice(2usize) } {
                OP_SYSCALL => h.handle_syscall(),
                OP_CPUID => h.handle_cpuid(),
                r => {
                    debugln!(h, "unsupported opcode: {:?}", r);
                    h.exit(1)
                }
            },

            _ => h.attacked(),
        }
    }

    fn handle_syscall(&mut self) {
        let ret = self.syscall(
            self.gpr.rdi.into(),
            self.gpr.rsi.into(),
            self.gpr.rdx.into(),
            self.gpr.r10.into(),
            self.gpr.r8.into(),
            self.gpr.r9.into(),
            self.gpr.rax.into(),
        );

        self.gpr.rip = (usize::from(self.gpr.rip) + 2).into();

        match ret {
            Err(e) => self.gpr.rax = (-e).into(),
            Ok([rax, rdx]) => {
                self.gpr.rax = rax.into();
                self.gpr.rdx = rdx.into();
            }
        }
    }

    fn handle_cpuid(&mut self) {
        debug!(
            self,
            "cpuid({:08x}, {:08x})",
            usize::from(self.gpr.rax),
            usize::from(self.gpr.rcx)
        );

        self.block.msg.req = request!(SYS_ENARX_CPUID => self.gpr.rax, self.gpr.rcx);

        unsafe {
            // prevent earlier writes from being moved beyond this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

            asm!("cpuid");

            // prevent later reads from being moved before this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

            self.gpr.rax = self.block.msg.req.arg[0].into();
            self.gpr.rbx = self.block.msg.req.arg[1].into();
            self.gpr.rcx = self.block.msg.req.arg[2].into();
            self.gpr.rdx = self.block.msg.req.arg[3].into();
        }

        debugln!(
            self,
            " = ({:08x}, {:08x}, {:08x}, {:08x})",
            usize::from(self.gpr.rax),
            usize::from(self.gpr.rbx),
            usize::from(self.gpr.rcx),
            usize::from(self.gpr.rdx)
        );

        self.gpr.rip = (usize::from(self.gpr.rip) + 2).into();
    }
}
