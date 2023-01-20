// SPDX-License-Identifier: Apache-2.0

use super::enarxcall::sgx_enarxcall;
#[cfg(feature = "gdb")]
use crate::backend::execute_gdb;
use crate::backend::Command;

use std::arch::asm;
use std::iter;
use std::mem::{size_of, MaybeUninit};
#[cfg(feature = "gdb")]
use std::net::TcpStream;
use std::sync::Arc;
use std::{io, ptr};

use anyhow::{bail, Context, Result};
use sallyport::item;
use sallyport::item::{Block, Item};
use sgx::enclu::{EENTER, EEXIT, ERESUME};
use sgx::ssa::Vector;
use tracing::{error, trace};
use vdso::Symbol;

pub struct Thread {
    keep: Arc<super::Keep>,
    vdso: &'static Symbol,
    tcs: super::Tcs,
    block: [Vec<usize>; 2],
    cssa: usize,
    how: usize,
    #[cfg(feature = "gdb")]
    gdb_fd: Option<TcpStream>,
}

impl Drop for Thread {
    fn drop(&mut self) {
        trace!("Dropping thread");
        self.keep.push_tcs(self.tcs)
    }
}

impl super::super::Keep for super::Keep {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn super::super::Thread>>> {
        let vdso = vdso::Vdso::locate()
            .expect("vDSO not found")
            .lookup("__vdso_sgx_enter_enclave")
            .expect("__vdso_sgx_enter_enclave not found");

        let tcs = self.tcs.write().unwrap().pop();

        let tcs = match tcs {
            Some(tcs) => tcs,
            None => return Ok(None),
        };

        let block = [
            vec![0; self.sallyport_block_size as usize / size_of::<usize>()],
            vec![0; self.sallyport_block_size as usize / size_of::<usize>()],
        ];

        Ok(Some(Box::new(Thread {
            keep: self,
            vdso,
            tcs,
            block,
            cssa: usize::default(),
            how: EENTER,
            #[cfg(feature = "gdb")]
            gdb_fd: None,
        })))
    }
}

impl super::super::Thread for Thread {
    fn enter(&mut self, _gdblisten: &Option<String>) -> Result<Command> {
        let mut run: Run = unsafe { MaybeUninit::zeroed().assume_init() };
        run.tcs = self.tcs as u64;
        let how = self.how;
        let exit_status: u64;
        use x86_64::registers::segmentation::Segment64;
        use x86_64::registers::segmentation::{FS, GS};

        let oldfs = FS::read_base().as_u64();
        let oldgs = GS::read_base().as_u64();

        let block = if self.cssa == 1 || self.cssa == 2 {
            self.block[self.cssa - 1].as_mut_ptr()
        } else {
            ptr::null_mut()
        };

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

                inout("rdi") block => _,
                lateout("rsi") _,
                lateout("rdx") _,
                inout("rcx") how => _,
                lateout("r8") exit_status,
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

        debug_assert_eq!(oldfs, FS::read_base().as_u64());
        debug_assert_eq!(oldgs, GS::read_base().as_u64());

        let exit_status = exit_status as i32;

        self.how = match run.function as usize {
            EENTER | ERESUME if run.vector == Vector::InvalidOpcode => EENTER,
            EENTER | ERESUME if run.vector == Vector::Page => {
                trace!(
                    ?run.vector,
                    run.exception_addr = ?(run.exception_addr as *const u8),
                    run.exception_error_code,
                    cssa = self.cssa
                );
                EENTER
            }
            EEXIT if self.cssa > 0 => ERESUME,
            EEXIT if self.cssa == 0 => {
                trace!("exit({exit_status})");
                return Ok(Command::Exit(exit_status as _));
            }

            _ => {
                if cfg!(feature = "dbg") {
                    error!(
                        ?run.vector,
                        run.exception_addr = ?(run.exception_addr as *const u8),
                        run.exception_error_code,
                        cssa = self.cssa,
                        "Unexpected exception",
                    );
                    EENTER
                } else {
                    panic!(
                        "Unexpected {:?}: address = {:>#016x}, error code = {:>#016b} cssa={}",
                        run.vector, run.exception_addr, run.exception_error_code, self.cssa
                    );
                }
            }
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

        if self.cssa > 4 {
            error!("SGX CSSA overflow");
            bail!("SGX CSSA overflow");
        }

        // Handle some potential sallyport contents
        if self.cssa == 1 || self.cssa == 2 {
            if let (EENTER, ERESUME) = (how, self.how) {
                let block: Block = self.block[self.cssa - 1].as_mut_slice().into();
                for item in block {
                    match item {
                        Item::Gdbcall(_gdbcall, _data) => {
                            #[cfg(feature = "gdb")]
                            unsafe {
                                execute_gdb(
                                    _gdbcall,
                                    _data,
                                    &mut self.gdb_fd,
                                    _gdblisten.as_ref().unwrap(),
                                )
                                .map_err(io::Error::from_raw_os_error)
                                .context("execute_gdb")?;
                            }
                        }

                        Item::Enarxcall(enarxcall, data) => {
                            sallyport::host::execute(
                                sgx_enarxcall(enarxcall, data, self.keep.clone())?.into_iter(),
                            )
                            .map_err(io::Error::from_raw_os_error)
                            .context("sallyport::host::execute")?;
                        }

                        // Catch exit for a clean shutdown
                        Item::Syscall(
                            item::Syscall {
                                num,
                                argv: [code, ..],
                                ..
                            },
                            ..,
                        ) if (*num == libc::SYS_exit as usize) => {
                            error!(
                                "exit({code}) syscall used over sallyport, when it should not be"
                            );
                            bail!(
                                "exit({code}) syscall used over sallyport, when it should not be"
                            );
                        }

                        // Catch exit_group for a clean shutdown
                        Item::Syscall(
                            item::Syscall {
                                num,
                                argv: [code, ..],
                                ..
                            },
                            ..,
                        ) if (*num == libc::SYS_exit_group as usize) => {
                            trace!("exit_group({code})");
                            std::process::exit(*code as _);
                        }

                        Item::Syscall(ref _syscall, ..) => {
                            #[cfg(feature = "dbg")]
                            match (
                                _syscall.num as libc::c_long,
                                _syscall.argv[1] as libc::c_int,
                            ) {
                                (
                                    libc::SYS_write | libc::SYS_read,
                                    libc::STDIN_FILENO | libc::STDOUT_FILENO | libc::STDERR_FILENO,
                                ) => {}
                                (libc::SYS_clock_gettime, _) => {}
                                _ => {
                                    dbg!(&_syscall);
                                }
                            }

                            sallyport::host::execute(iter::once(item))
                                .map_err(io::Error::from_raw_os_error)
                                .context("sallyport::host::execute")?;
                        }
                    }
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
