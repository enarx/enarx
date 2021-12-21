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
        if $crate::DEBUG {
            use core::fmt::Write;
            let _ = writeln!($dst, $($arg)*);
        }
    };
}

mod base;
mod enarx;
mod file;
pub(crate) mod gdb;
mod memory;
mod other;
mod process;

use core::arch::asm;
use core::fmt::Write;
use core::mem::size_of;
use core::ptr::read_unaligned;

use crate::{DEBUG, ENARX_EXEC_END, ENARX_EXEC_START, ENCL_SIZE};
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
    fn new(ssa: &'a mut StateSaveArea, block: &'a mut Block) -> Self {
        Self { ssa, block }
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
    pub fn handle(ssa: &'a mut StateSaveArea, block: &'a mut Block) {
        let mut h = Self::new(ssa, block);

        match h.ssa.vector() {
            Some(ExceptionVector::InvalidOpcode) => {
                match unsafe { read_unaligned(h.ssa.gpr.rip as _) } {
                    OP_SYSCALL => h.handle_syscall(),
                    OP_CPUID => h.handle_cpuid(),
                    r => {
                        debugln!(h, "unsupported opcode: {:#04x}", r);
                        h.print_ssa_stack_trace();

                        #[cfg(feature = "gdb")]
                        if r as u8 == 0xCC {
                            let rip = h.ssa.gpr.rip;
                            if unsafe { crate::handler::gdb::unset_bp(rip) } {
                                debugln!(h, "unset_bp: {:#x}", rip);
                            }
                        }

                        #[cfg(feature = "gdb")]
                        h.gdb_session();

                        if r == unsafe { read_unaligned(h.ssa.gpr.rip as _) } {
                            h.exit(1)
                        }
                    }
                }
            }

            #[cfg(feature = "gdb")]
            Some(ExceptionVector::Page) => {
                h.print_ssa_stack_trace();
                h.gdb_session();
                h.exit(1)
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

    /// Print a stack trace using the SSA registers.
    fn print_ssa_stack_trace(&mut self) {
        if DEBUG {
            unsafe { self.print_stack_trace(self.ssa.gpr.rip, self.ssa.gpr.rbp) }
        }
    }

    /// Print out `rip` relative to the shim (S) or the exec (E) base address.
    ///
    /// This can be used with `addr2line` and the executable with debug info
    /// to get the function name and line number.
    unsafe fn print_rip(&mut self, rip: u64) {
        let shim_start = ENCL_SIZE as u64;
        let enarx_exec_start = &ENARX_EXEC_START as *const _ as u64;
        let enarx_exec_end = &ENARX_EXEC_END as *const _ as u64;

        let exec_range = enarx_exec_start..enarx_exec_end;

        if exec_range.contains(&rip) {
            let rip_pie = rip - enarx_exec_start;
            debugln!(self, "E {:>#016x}", rip_pie);
        } else {
            let rip_pie = (shim_start - 1) & rip;
            debugln!(self, "S {:>#016x}", rip_pie);
        }
    }

    /// Print a stack trace with the old `rbp` stack frame pointers
    unsafe fn print_stack_trace(&mut self, rip: u64, mut rbp: u64) {
        // TODO: parse the elf and actually find the text sections.
        let encl_start = self as *const _ as u64 / ENCL_SIZE as u64 * ENCL_SIZE as u64;
        let encl_end = encl_start + ENCL_SIZE as u64;
        let encl_range = encl_start..encl_end;

        debugln!(self, "TRACE:");

        self.print_rip(rip);

        // Maximum 64 frames
        for _frame in 0..64 {
            if rbp == 0 || rbp & 7 != 0 {
                break;
            }

            if !encl_range.contains(&rbp) {
                debugln!(self, "invalid rbp: {:>#016x}", rbp);
                break;
            }

            match rbp.checked_add(size_of::<usize>() as _) {
                None => break,
                Some(rip_rbp) => {
                    let rip = *(rip_rbp as *const u64);
                    match rip.checked_sub(1) {
                        None => break,
                        Some(0) => break,
                        Some(rip) => {
                            self.print_rip(rip);
                            rbp = *(rbp as *const u64);
                        }
                    }
                }
            }
        }
    }
}
