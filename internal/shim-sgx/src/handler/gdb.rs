// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "gdb")]

use core::arch::asm;
use core::convert::TryFrom;
use core::mem::size_of;
use core::ops::Range;

use crate::heap::HEAP;
use crate::{ENARX_EXEC_START, ENCL_SIZE};
use gdbstub::arch::Arch;
use gdbstub::target::ext::base::singlethread::SingleThreadOps;
use gdbstub::target::ext::base::singlethread::{GdbInterrupt, ResumeAction, StopReason};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::{Target, TargetResult};
use gdbstub::Connection;
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use primordial::Register;
use sallyport::syscall::{
    ProcessSyscallHandler, SyscallHandler, SYS_ENARX_GDB_PEEK, SYS_ENARX_GDB_READ,
    SYS_ENARX_GDB_START, SYS_ENARX_GDB_WRITE,
};
use sallyport::Block;
use sgx::ssa::StateSaveArea;
use x86_64::registers::rflags::RFlags;

impl<'a> super::Handler<'a> {
    pub(crate) fn gdb_session(&mut self) {
        use gdbstub::{DisconnectReason, GdbStubBuilder, GdbStubError};

        let mut mxcsr: u32 = 0;
        unsafe { asm!("stmxcsr [{}]", in(reg) &mut mxcsr, options(nostack)) };

        let regs = X86_64CoreRegs {
            /// RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
            regs: [
                self.ssa.gpr.rax,
                self.ssa.gpr.rbx,
                self.ssa.gpr.rcx,
                self.ssa.gpr.rdx,
                self.ssa.gpr.rsi,
                self.ssa.gpr.rdi,
                self.ssa.gpr.rbp,
                self.ssa.gpr.rsp,
                self.ssa.gpr.r8,
                self.ssa.gpr.r9,
                self.ssa.gpr.r10,
                self.ssa.gpr.r11,
                self.ssa.gpr.r12,
                self.ssa.gpr.r13,
                self.ssa.gpr.r14,
                self.ssa.gpr.r15,
            ],
            eflags: self.ssa.gpr.rflags as u32,
            rip: self.ssa.gpr.rip,
            segments: Default::default(),
            /// FPU registers: ST0 through ST7
            st: Default::default(),
            fpu: Default::default(),
            xmm: Default::default(),
            mxcsr,
        };

        regs.regs.iter().enumerate().for_each(|(i, v)| {
            debugln!(self, "r{} = {:#x}", i, v);
        });

        debugln!(self, "rip = {:#x}", regs.rip);

        let block_ptr = self.block as *const _ as *const u8;
        let block_range = block_ptr..unsafe { block_ptr.add(size_of::<Block>()) };
        let ssa_ptr = self.ssa as *const _ as *const u8;
        let ssa_range = ssa_ptr..unsafe { ssa_ptr.add(size_of::<StateSaveArea>()) };

        let mut target = GdbTarget::new(regs, block_range, ssa_range);

        let mut buf = [0; 4096];
        debugln!(self, "Starting GDB session...");
        debugln!(self, "symbol-file -o {:#x} <shim>", shim_base_offset());
        debugln!(self, "symbol-file -o {:#x} <exec>", unsafe {
            &ENARX_EXEC_START as *const u8 as u64
        });

        // workaround for the gdbstub main loop (will change with gdbstub-0.6
        loop {
            let mut gdb = GdbStubBuilder::new(self as &mut dyn Connection<Error = libc::c_int>)
                .with_packet_buffer(&mut buf)
                .build()
                .unwrap();

            match gdb.run(&mut target) {
                Ok(disconnect_reason) => {
                    match disconnect_reason {
                        DisconnectReason::Disconnect => debugln!(self, "GDB Disconnected"),
                        DisconnectReason::TargetExited(_) => debugln!(self, "Target exited"),
                        DisconnectReason::TargetTerminated(_) => debugln!(self, "Target halted"),
                        DisconnectReason::Kill => {
                            debugln!(self, "GDB sent a kill command");
                            self.exit(255);
                        }
                    }
                    break;
                }

                Err(GdbStubError::TargetError(e)) => {
                    debugln!(self, "resume: {:#?}", e);
                    break;
                }

                // workaround for the gdbstub main loop (will change with gdbstub-0.6
                Err(e) => match e {
                    GdbStubError::ConnectionRead(_) => break,
                    GdbStubError::ConnectionWrite(_) => break,
                    GdbStubError::PacketParse(_) => break,
                    GdbStubError::PacketUnexpected => break,
                    GdbStubError::TargetMismatch => break,
                    GdbStubError::UnsupportedStopReason => break,
                    _ => debugln!(self, "gdbstub internal error: {:#?}", e),
                },
            };
        }

        target.regs.regs.iter().enumerate().for_each(|(i, v)| {
            debugln!(self, "r{} = {:#x}", i, v);
        });

        debugln!(self, "rip = {:#x}", target.regs.rip);

        // update the registers
        self.ssa.gpr.rax = target.regs.regs[0];
        self.ssa.gpr.rbx = target.regs.regs[1];
        self.ssa.gpr.rcx = target.regs.regs[2];
        self.ssa.gpr.rdx = target.regs.regs[3];
        self.ssa.gpr.rsi = target.regs.regs[4];
        self.ssa.gpr.rdi = target.regs.regs[5];
        self.ssa.gpr.rbp = target.regs.regs[6];
        self.ssa.gpr.rip = target.regs.regs[7];
        self.ssa.gpr.r8 = target.regs.regs[8];
        self.ssa.gpr.r9 = target.regs.regs[9];
        self.ssa.gpr.r10 = target.regs.regs[10];
        self.ssa.gpr.r11 = target.regs.regs[11];
        self.ssa.gpr.r12 = target.regs.regs[12];
        self.ssa.gpr.r13 = target.regs.regs[13];
        self.ssa.gpr.r14 = target.regs.regs[14];
        self.ssa.gpr.r15 = target.regs.regs[15];
        self.ssa.gpr.rip = target.regs.rip;
        self.ssa.gpr.rflags &= 0xFFFF_FFFF_0000_0000;
        self.ssa.gpr.rflags |= target.regs.eflags as u64;
    }
}

impl<'a> gdbstub::Connection for super::Handler<'a> {
    type Error = libc::c_int;

    fn read(&mut self) -> Result<u8, Self::Error> {
        let mut buf = [0u8];
        match self.read_exact(&mut buf) {
            Ok(_) => Ok(buf[0]),
            Err(e) => Err(e),
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        let bytes_len = buf.len();
        let mut to_read = bytes_len;

        loop {
            let next = bytes_len.checked_sub(to_read).ok_or(libc::EFAULT)?;

            let [read, _] = SyscallHandler::syscall(
                self,
                Register::<usize>::from(buf[next..].as_mut_ptr()),
                Register::<usize>::from(to_read),
                0usize.into(),
                0usize.into(),
                0usize.into(),
                0usize.into(),
                SYS_ENARX_GDB_READ as _,
            )?;

            // be careful with `read` as it is untrusted
            to_read = to_read.checked_sub(read.into()).ok_or(libc::EIO)?;

            if to_read == 0 {
                break;
            }
        }

        Ok(())
    }

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.write_all(&[byte])
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        let bytes_len = buf.len();
        let mut to_write = bytes_len;

        loop {
            let next = bytes_len.checked_sub(to_write).ok_or(libc::EFAULT)?;

            let [written, _] = self.syscall(
                Register::<usize>::from(buf[next..].as_ptr()),
                Register::<usize>::from(to_write),
                0usize.into(),
                0usize.into(),
                0usize.into(),
                0usize.into(),
                SYS_ENARX_GDB_WRITE as _,
            )?;

            // be careful with `written` as it is untrusted
            to_write = to_write.checked_sub(written.into()).ok_or(libc::EIO)?;
            if to_write == 0 {
                break;
            }
        }

        Ok(())
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        let [val, _] = self.syscall(
            0usize.into(),
            0usize.into(),
            0usize.into(),
            0usize.into(),
            0usize.into(),
            0usize.into(),
            SYS_ENARX_GDB_PEEK as _,
        )?;

        Ok(u8::try_from(usize::from(val)).ok())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn on_session_start(&mut self) -> Result<(), Self::Error> {
        let [_, _] = self.syscall(
            0usize.into(),
            0usize.into(),
            0usize.into(),
            0usize.into(),
            0usize.into(),
            0usize.into(),
            SYS_ENARX_GDB_START as _,
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct GdbTarget {
    regs: X86_64CoreRegs,
    shim_range: Range<*const u8>,
    block_range: Range<*const u8>,
    ssa_range: Range<*const u8>,
}

impl GdbTarget {
    pub fn new(
        regs: X86_64CoreRegs,
        block_range: Range<*const u8>,
        ssa_range: Range<*const u8>,
    ) -> Self {
        let start = shim_base_offset() as *const u8;
        let end = HEAP.read().range().end;
        let shim_range = start..end;

        Self {
            regs,
            shim_range,
            block_range,
            ssa_range,
        }
    }
}

#[derive(Debug)]
pub enum GdbTargetError {
    ResumeContinue,
    ResumeStep,
    ResumeContinueWithSignal,
    ResumeStepWithSignal,
    // ReadMemoryOutOfRange(u64),
    WriteMemoryOutOfRange(u64),
}

impl Target for GdbTarget {
    type Arch = gdbstub_arch::x86::X86_64_SSE;
    type Error = GdbTargetError;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }
}

impl SingleThreadOps for GdbTarget {
    fn resume(
        &mut self,
        action: ResumeAction,
        _gdb_interrupt: GdbInterrupt<'_>,
    ) -> Result<StopReason<<Self::Arch as Arch>::Usize>, Self::Error> {
        match action {
            ResumeAction::Continue => {
                self.regs.eflags &= !RFlags::TRAP_FLAG.bits() as u32;
                Err(GdbTargetError::ResumeContinue)
            }
            ResumeAction::Step => {
                self.regs.eflags |= RFlags::TRAP_FLAG.bits() as u32;
                Err(GdbTargetError::ResumeStep)
            }
            ResumeAction::ContinueWithSignal(_) => {
                self.regs.eflags &= !RFlags::TRAP_FLAG.bits() as u32;
                Err(GdbTargetError::ResumeContinueWithSignal)
            }
            ResumeAction::StepWithSignal(_) => {
                self.regs.eflags |= RFlags::TRAP_FLAG.bits() as u32;
                Err(GdbTargetError::ResumeStepWithSignal)
            }
        }
    }

    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        *regs = self.regs.clone();
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        self.regs = regs.clone();
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<(), Self> {
        let ptr = start_addr as *const u8;
        let ptr_end = unsafe { ptr.add(data.len()) };

        if !((self.shim_range.contains(&ptr) && self.shim_range.contains(&ptr_end))
            || (self.block_range.contains(&ptr) && self.block_range.contains(&ptr_end))
            || (self.ssa_range.contains(&ptr) && self.ssa_range.contains(&ptr_end)))
        {
            return Err(gdbstub::target::TargetError::NonFatal);
        }

        let src = unsafe { core::slice::from_raw_parts(ptr, data.len()) };
        data.copy_from_slice(src);
        Ok(())
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        let ptr = start_addr as *const u8;
        let ptr_end = unsafe { ptr.add(data.len()) };

        if !((self.shim_range.contains(&ptr) && self.shim_range.contains(&ptr_end))
            || (self.block_range.contains(&ptr) && self.block_range.contains(&ptr_end))
            || (self.ssa_range.contains(&ptr) && self.ssa_range.contains(&ptr_end)))
        {
            return Err(gdbstub::target::TargetError::Fatal(
                GdbTargetError::WriteMemoryOutOfRange(start_addr as _),
            ));
        }

        let ptr = start_addr as *mut u8;

        let dst = unsafe { core::slice::from_raw_parts_mut(ptr, data.len()) };
        dst.copy_from_slice(data);
        Ok(())
    }
}

fn shim_base_offset() -> u64 {
    let base: u64;
    unsafe {
        asm!(
            "lea    {0},    [rip + _DYNAMIC]", // rdi = address of _DYNAMIC section
            "and    {0},    -{SIZE}         ", // rsi = relocation address
            out(reg) base,
            SIZE = const ENCL_SIZE,
            options(nostack, nomem)
        );
    }
    base
}

static mut TRACE_BYTE: (u64, u8) = (0, 0);

pub unsafe fn set_bp(rip: u64) {
    let ptr = rip as *mut u8;

    TRACE_BYTE = (rip, ptr.read());
    // Write INT3
    ptr.write(0xCC);
}

pub unsafe fn unset_bp(rip: u64) -> bool {
    let ptr = rip as *mut u8;

    if rip != TRACE_BYTE.0 {
        return false;
    }

    debug_assert_eq!(ptr.read(), 0xCC);

    ptr.write(TRACE_BYTE.1);

    TRACE_BYTE = (0, 0);

    true
}
