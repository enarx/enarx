// SPDX-License-Identifier: Apache-2.0

use super::super::Command;
use crate::backend::sgx::attestation::get_attestation;

use std::arch::asm;
use std::mem::MaybeUninit;
#[cfg(feature = "gdb")]
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::Result;
use sallyport::{syscall::SYS_ENARX_CPUID, Block};
use sgx::enclu::{EENTER, EEXIT, ERESUME};
use sgx::ssa::Vector;
use vdso::Symbol;

pub struct Thread {
    enclave: Arc<super::Keep>,
    vdso: &'static Symbol,
    tcs: *const super::Tcs,
    block: Block,
    cssa: usize,
    how: usize,
    #[cfg(feature = "gdb")]
    gdb_fd: Option<TcpStream>,
}

impl Drop for Thread {
    fn drop(&mut self) {
        self.enclave.tcs.write().unwrap().push(self.tcs)
    }
}

impl super::super::Keep for super::Keep {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn super::super::Thread>>> {
        let vdso = vdso::Vdso::locate()
            .expect("vDSO not found")
            .lookup("__vdso_sgx_enter_enclave")
            .expect("__vdso_sgx_enter_enclave not found");

        let tcs = match self.tcs.write().unwrap().pop() {
            Some(tcs) => tcs,
            None => return Ok(None),
        };

        Ok(Some(Box::new(Thread {
            enclave: self,
            vdso,
            tcs,
            block: Block::default(),
            cssa: usize::default(),
            how: EENTER,
            #[cfg(feature = "gdb")]
            gdb_fd: None,
        })))
    }
}

impl super::super::Thread for Thread {
    fn enter(&mut self) -> Result<Command<'_>> {
        let mut run: Run = unsafe { MaybeUninit::zeroed().assume_init() };
        run.tcs = self.tcs as u64;
        let how = self.how;

        // The `enclu` instruction consumes `rax`, `rbx` and `rcx`. However,
        // the vDSO function preserves `rbx` AND sets `rax` as the return
        // value. All other registers are passed to and from the enclave
        // unmodified.
        unsafe {
            asm!(
                "push rbx",       // save rbx
                "push rbp",       // save rbp
                "mov  rbp, rsp",  // save rsp
                "and  rsp, ~0xf", // align to 16+0

                "push 0",         // align to 16+8
                "push r10",       // push run address
                "call r11",       // call vDSO function

                "mov  rsp, rbp",  // restore rsp
                "pop  rbp",       // restore rbp
                "pop  rbx",       // restore rbx

                inout("rdi") &self.block => _,
                lateout("rsi") _,
                lateout("rdx") _,
                inout("rcx") how => _,
                lateout("r8") _,
                lateout("r9") _,
                inout("r10") &mut run => _,
                inout("r11") self.vdso => _,
                lateout("r12") _,
                lateout("r13") _,
                lateout("r14") _,
                lateout("r15") _,
                lateout("rax") _,
            );
        }

        self.how = match run.function as usize {
            EENTER | ERESUME if run.vector == Vector::InvalidOpcode => EENTER,

            #[cfg(feature = "gdb")]
            EENTER | ERESUME if run.vector == Vector::Page => EENTER,

            EEXIT => ERESUME,

            _ => panic!("Unexpected AEX: {:?}", run.vector),
        };

        // Keep track of the CSSA
        match self.how {
            EENTER => self.cssa += 1,
            ERESUME => match self.cssa {
                0 => unreachable!(),
                _ => self.cssa -= 1,
            },
            _ => unreachable!(),
        }

        // If we have handled an InvalidOpcode error, evaluate the sallyport.
        //
        // Currently, we have no way to know if the sallyport contains a valid
        // request by evaluating the sallyport directly. So we must presume
        // that the sallyport is only valid when moving from CSSA 2 to CSSA 1.
        //
        // After the sallyport rework, we can test the sallyport itself and
        // remove this logic.
        if self.cssa > 0 {
            if let (EENTER, ERESUME) = (how, self.how) {
                match unsafe { self.block.msg.req }.num.into() {
                    SYS_ENARX_CPUID => return Ok(Command::CpuId(&mut self.block)),

                    #[cfg(feature = "gdb")]
                    sallyport::syscall::SYS_ENARX_GDB_START
                    | sallyport::syscall::SYS_ENARX_GDB_PEEK
                    | sallyport::syscall::SYS_ENARX_GDB_READ
                    | sallyport::syscall::SYS_ENARX_GDB_WRITE => {
                        return Ok(Command::Gdb(&mut self.block, &mut self.gdb_fd))
                    }

                    sallyport::syscall::SYS_ENARX_GETATT => {
                        self.block.msg.rep = unsafe {
                            get_attestation(
                                self.block.msg.req.arg[0].into(),
                                self.block.msg.req.arg[1].into(),
                                self.block.msg.req.arg[2].into(),
                                self.block.msg.req.arg[3].into(),
                            )
                            .map(|v| [v.into(), 0usize.into()])
                            .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL))
                            .into()
                        };

                        return Ok(Command::Continue);
                    }

                    _ => return Ok(Command::SysCall(&mut self.block)),
                }
            }
        }

        Ok(Command::Continue)
    }
}

// This structure is defined by the Linux kernel.
//
// See: https://github.com/torvalds/linux/blob/84292fffc2468125632a21c09533a89426ea212e/arch/x86/include/uapi/asm/sgx.h#L112
#[repr(C)]
#[derive(Debug)]
struct Run {
    tcs: u64,
    function: u32,
    vector: Vector,
    padding: u8,
    exception_error_code: u16,
    exception_addr: u64,
    user_handler: u64,
    user_data: u64,
    reserved: [u64; 27],
}
