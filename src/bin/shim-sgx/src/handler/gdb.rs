// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "gdb")]

use core::arch::asm;
use core::ffi::c_int;
use core::mem::size_of;
use core::ops::Range;

use crate::handler::HEAP;
use crate::{shim_address, BLOCK_SIZE, ENARX_EXEC_START};
use gdbstub::arch::Arch;
use gdbstub::target::ext::base::singlethread::SingleThreadOps;
use gdbstub::target::ext::base::singlethread::{GdbInterrupt, ResumeAction, StopReason};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub::Connection;
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use sallyport::guest::Handler;
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

        let block_start = self.block.as_ptr() as usize;
        let block_range = block_start..block_start + BLOCK_SIZE;
        let ssa_start = self.ssa as *const _ as usize;
        let ssa_range = ssa_start..ssa_start + size_of::<StateSaveArea>();

        let mut target = GdbTarget::new(regs, block_range, ssa_range);

        let mut buf = [0; 4096];
        debugln!(self, "Starting GDB session...");
        debugln!(self, "symbol-file -o {:#x} <shim>", shim_address());
        debugln!(self, "symbol-file -o {:#x} <exec>", unsafe {
            &ENARX_EXEC_START as *const u8 as u64
        });

        // workaround for the gdbstub main loop (will change with gdbstub-0.6
        loop {
            let mut gdb = GdbStubBuilder::new(self as &mut dyn Connection<Error = c_int>)
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
                            self.exit_group(255).unwrap();
                            unreachable!()
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
    type Error = c_int;

    fn read(&mut self) -> Result<u8, Self::Error> {
        self.gdb_read()
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        for byte in buf.iter_mut() {
            *byte = self.gdb_read()?;
        }

        Ok(())
    }

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.write_all(&[byte])
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.gdb_write_all(buf)?;
        Ok(())
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        self.gdb_peek()
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn on_session_start(&mut self) -> Result<(), Self::Error> {
        self.gdb_on_session_start()
    }
}

#[derive(Debug)]
pub(crate) struct GdbTarget {
    regs: X86_64CoreRegs,
    shim_range: Range<usize>,
    block_range: Range<usize>,
    ssa_range: Range<usize>,
}

impl GdbTarget {
    pub fn new(regs: X86_64CoreRegs, block_range: Range<usize>, ssa_range: Range<usize>) -> Self {
        let start = shim_address() as usize;
        let end = HEAP.read().range().end as usize;
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
        let start_addr = start_addr as usize;
        let end_addr = start_addr
            .checked_add(data.len())
            .ok_or(TargetError::NonFatal)?;

        if !((self.shim_range.contains(&start_addr) && self.shim_range.contains(&end_addr))
            || (self.block_range.contains(&start_addr) && self.block_range.contains(&end_addr))
            || (self.ssa_range.contains(&start_addr) && self.ssa_range.contains(&end_addr)))
        {
            return Err(TargetError::NonFatal);
        }

        let src = unsafe { core::slice::from_raw_parts(start_addr as *const u8, data.len()) };
        data.copy_from_slice(src);
        Ok(())
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        let start_addr = start_addr as usize;
        let end_addr = start_addr
            .checked_add(data.len())
            .ok_or(TargetError::Fatal(GdbTargetError::WriteMemoryOutOfRange(
                start_addr as _,
            )))?;

        if !((self.shim_range.contains(&start_addr) && self.shim_range.contains(&end_addr))
            || (self.block_range.contains(&start_addr) && self.block_range.contains(&end_addr))
            || (self.ssa_range.contains(&start_addr) && self.ssa_range.contains(&end_addr)))
        {
            return Err(TargetError::Fatal(GdbTargetError::WriteMemoryOutOfRange(
                start_addr as _,
            )));
        }

        let ptr = start_addr as *mut u8;

        let dst = unsafe { core::slice::from_raw_parts_mut(ptr, data.len()) };
        dst.copy_from_slice(data);
        Ok(())
    }
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
