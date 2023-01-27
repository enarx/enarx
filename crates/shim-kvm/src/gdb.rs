// SPDX-License-Identifier: Apache-2.0

//! GDB debugging

#![cfg(feature = "gdb")]

use crate::exec::EXEC_READY;
use crate::hostcall::{HostCall, SHIM_LOCAL_STORAGE};
use crate::interrupts::ExtendedInterruptStackFrameValue;

use core::arch::asm;
use core::ffi::c_int;
use core::sync::atomic::Ordering;

use crate::addr::SHIM_VIRT_OFFSET;
use crate::exec::EXEC_VIRT_ADDR;
use crate::paging::SHIM_PAGETABLE;
use gdbstub::arch::Arch;
use gdbstub::target::ext::base::singlethread::SingleThreadOps;
use gdbstub::target::ext::base::singlethread::{GdbInterrupt, ResumeAction, StopReason};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub::{DisconnectReason, GdbStubBuilder, GdbStubError};
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use sallyport::guest::Handler;
use sallyport::libc::EIO;
use x86_64::registers::rflags::RFlags;
use x86_64::structures::paging::Translate;
use x86_64::VirtAddr;

pub(crate) struct GdbConnection(());

impl GdbConnection {
    pub fn new() -> Self {
        Self(())
    }
}

impl gdbstub::Connection for GdbConnection {
    type Error = c_int;

    fn read(&mut self) -> Result<u8, Self::Error> {
        let mut tls = SHIM_LOCAL_STORAGE.write();
        let mut host_call = HostCall::try_new(&mut tls).ok_or(EIO)?;

        host_call.gdb_read()
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        let mut tls = SHIM_LOCAL_STORAGE.write();
        let mut host_call = HostCall::try_new(&mut tls).ok_or(EIO)?;

        for byte in buf.iter_mut() {
            *byte = host_call.gdb_read()?;
        }

        Ok(())
    }

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.write_all(&[byte])
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        let mut tls = SHIM_LOCAL_STORAGE.write();
        let mut host_call = HostCall::try_new(&mut tls).ok_or(EIO)?;

        host_call.gdb_write_all(buf)?;
        Ok(())
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        let mut tls = SHIM_LOCAL_STORAGE.write();
        let mut host_call = HostCall::try_new(&mut tls).ok_or(EIO)?;
        host_call.gdb_peek()
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn on_session_start(&mut self) -> Result<(), Self::Error> {
        let mut tls = SHIM_LOCAL_STORAGE.write();
        let mut host_call = HostCall::try_new(&mut tls).ok_or(EIO)?;
        host_call.gdb_on_session_start()
    }
}

#[derive(Debug)]
pub(crate) enum GdbTargetError {
    ResumeContinue,
    ResumeStep,
    ResumeContinueWithSignal,
    ResumeStepWithSignal,
    // ReadMemoryOutOfRange(u64),
    WriteMemoryOutOfRange(u64),
}

#[derive(Debug)]
pub(crate) struct GdbTarget<'a> {
    frame: &'a mut ExtendedInterruptStackFrameValue,
}

impl<'a> GdbTarget<'a> {
    pub(crate) fn new(frame: &'a mut ExtendedInterruptStackFrameValue) -> Self {
        Self { frame }
    }
}

impl Target for GdbTarget<'_> {
    type Arch = gdbstub_arch::x86::X86_64_SSE;
    type Error = GdbTargetError;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }
}

impl SingleThreadOps for GdbTarget<'_> {
    fn resume(
        &mut self,
        action: ResumeAction,
        _gdb_interrupt: GdbInterrupt<'_>,
    ) -> Result<StopReason<<Self::Arch as Arch>::Usize>, Self::Error> {
        match action {
            ResumeAction::Continue => {
                self.frame.cpu_flags &= !RFlags::TRAP_FLAG.bits();
                Err(GdbTargetError::ResumeContinue)
            }
            ResumeAction::Step => {
                self.frame.cpu_flags |= RFlags::TRAP_FLAG.bits();
                Err(GdbTargetError::ResumeStep)
            }
            ResumeAction::ContinueWithSignal(_) => {
                self.frame.cpu_flags &= !RFlags::TRAP_FLAG.bits();
                Err(GdbTargetError::ResumeContinueWithSignal)
            }
            ResumeAction::StepWithSignal(_) => {
                self.frame.cpu_flags |= RFlags::TRAP_FLAG.bits();
                Err(GdbTargetError::ResumeStepWithSignal)
            }
        }
    }

    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        *regs = (self.frame as &ExtendedInterruptStackFrameValue).into();
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        self.frame.rax = regs.regs[0];
        self.frame.rbx = regs.regs[1];
        self.frame.rcx = regs.regs[2];
        self.frame.rdx = regs.regs[3];
        self.frame.rsi = regs.regs[4];
        self.frame.rdi = regs.regs[5];
        self.frame.rbp = regs.regs[6];
        self.frame.stack_pointer = unsafe { VirtAddr::new_unsafe(regs.regs[7]) };
        self.frame.r8 = regs.regs[8];
        self.frame.r9 = regs.regs[9];
        self.frame.r10 = regs.regs[10];
        self.frame.r11 = regs.regs[11];
        self.frame.r12 = regs.regs[12];
        self.frame.r13 = regs.regs[13];
        self.frame.r14 = regs.regs[14];
        self.frame.r15 = regs.regs[15];
        self.frame.instruction_pointer = unsafe { VirtAddr::new_unsafe(regs.rip) };
        self.frame.cpu_flags &= 0xFFFF_FFFF_0000_0000;
        self.frame.cpu_flags |= regs.eflags as u64;
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<(), Self> {
        let ptr = start_addr as *const u8;

        let _phys = SHIM_PAGETABLE
            .read()
            .translate_addr(VirtAddr::from_ptr(ptr))
            .ok_or(TargetError::NonFatal)?;
        let _phys_end = SHIM_PAGETABLE
            .read()
            .translate_addr(VirtAddr::from_ptr(unsafe { ptr.add(data.len()) }))
            .ok_or(TargetError::NonFatal)?;

        //eprintln!("read_addrs: {:?} size {}", ptr, data.len());
        let src = unsafe { core::slice::from_raw_parts(ptr, data.len()) };
        data.copy_from_slice(src);
        Ok(())
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        let ptr = start_addr as *mut u8;

        let _phys = SHIM_PAGETABLE
            .read()
            .translate_addr(VirtAddr::from_ptr(ptr))
            .ok_or(TargetError::Fatal(GdbTargetError::WriteMemoryOutOfRange(
                start_addr,
            )))?;
        let _phys_end = SHIM_PAGETABLE
            .read()
            .translate_addr(VirtAddr::from_ptr(unsafe { ptr.add(data.len()) }))
            .ok_or(TargetError::Fatal(GdbTargetError::WriteMemoryOutOfRange(
                start_addr,
            )))?;

        //eprintln!("write_addrs: {:?} size {}", ptr, data.len());
        let dst = unsafe { core::slice::from_raw_parts_mut(ptr, data.len()) };
        dst.copy_from_slice(data);
        Ok(())
    }
}

impl From<&ExtendedInterruptStackFrameValue> for X86_64CoreRegs {
    fn from(frame: &ExtendedInterruptStackFrameValue) -> Self {
        let mut mxcsr: u32 = 0;
        unsafe { asm!("stmxcsr [{}]", in(reg) &mut mxcsr, options(nostack)) };

        Self {
            regs: [
                frame.rax,
                frame.rbx,
                frame.rcx,
                frame.rdx,
                frame.rsi,
                frame.rdi,
                frame.rbp,
                frame.stack_pointer.as_u64(),
                frame.r8,
                frame.r9,
                frame.r10,
                frame.r11,
                frame.r12,
                frame.r13,
                frame.r14,
                frame.r15,
            ],
            eflags: frame.cpu_flags as u32,
            rip: frame.instruction_pointer.as_u64(),
            segments: Default::default(),
            st: Default::default(),
            fpu: Default::default(),
            xmm: Default::default(),
            mxcsr,
        }
    }
}

pub(crate) fn gdb_session(stack_frame: &mut ExtendedInterruptStackFrameValue) {
    let regs: X86_64CoreRegs = (stack_frame as &ExtendedInterruptStackFrameValue).into();
    regs.regs
        .iter()
        .enumerate()
        .for_each(|(i, v)| eprintln!("r{i} = {v:#x}"));

    let mut target = GdbTarget::new(stack_frame);

    let mut buf = [0; 4096];

    eprintln!("Starting GDB session...");

    eprintln!("symbol-file -o {SHIM_VIRT_OFFSET:#x} <shim>");

    if EXEC_READY.load(Ordering::Relaxed) {
        let exec_virt = *EXEC_VIRT_ADDR.read();
        eprintln!(
            "add-symbol-file -o {:?} <exec>",
            exec_virt.as_mut_ptr::<u8>()
        );
    }

    loop {
        let conn = GdbConnection::new();
        let mut gdb = GdbStubBuilder::new(conn)
            .with_packet_buffer(&mut buf)
            .build()
            .unwrap();

        match gdb.run(&mut target) {
            Ok(disconnect_reason) => {
                match disconnect_reason {
                    DisconnectReason::Disconnect => eprintln!("GDB Disconnected"),
                    DisconnectReason::TargetExited(_) => eprintln!("Target exited"),
                    DisconnectReason::TargetTerminated(_) => eprintln!("Target halted"),
                    DisconnectReason::Kill => eprintln!("GDB sent a kill command"),
                }
                break;
            }

            Err(GdbStubError::TargetError(e)) => {
                eprintln!("resume: {e:#?}");
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
                _ => eprintln!("gdbstub internal error: {e:#?}"),
            },
        };
    }
}
