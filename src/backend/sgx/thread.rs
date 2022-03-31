// SPDX-License-Identifier: Apache-2.0

use super::attestation::{get_attestation_key_id, get_key_size, get_quote, get_target_info};
#[cfg(feature = "gdb")]
use crate::backend::execute_gdb;
use crate::backend::Command;

use std::arch::asm;
use std::arch::x86_64::CpuidResult;
use std::io;
use std::iter;
use std::mem::{size_of, MaybeUninit};
#[cfg(feature = "gdb")]
use std::net::TcpStream;
use std::sync::Arc;

use crate::backend::sgx::attestation::get_quote_size;
use anyhow::{Context, Result};
use sallyport::host::{deref_aligned, deref_slice};
use sallyport::item;
use sallyport::item::enarxcall::sgx::{Report, TargetInfo};
use sallyport::item::enarxcall::Payload;
use sallyport::item::{Block, Item};
use sgx::enclu::{EENTER, EEXIT, ERESUME};
use sgx::ssa::Vector;
use vdso::Symbol;

pub struct Thread {
    enclave: Arc<super::Keep>,
    vdso: &'static Symbol,
    tcs: *const super::Tcs,
    block: Vec<usize>,
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

        let block = vec![0; self.sallyport_block_size as usize / size_of::<usize>()];

        Ok(Some(Box::new(Thread {
            enclave: self,
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

fn sgx_enarxcall<'a>(enarxcall: &'a mut Payload, data: &'a mut [u8]) -> Result<Option<Item<'a>>> {
    match enarxcall {
        item::Enarxcall {
            num: item::enarxcall::Number::Cpuid,
            argv: [leaf, subleaf, cpuid_offset, ..],
            ret,
        } => {
            let cpuid_buf = unsafe {
                // Safety: `deref_aligned` gives us a pointer to an aligned `CpuidResult` struct.
                // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                // is a subslice of.
                &mut *deref_aligned::<MaybeUninit<CpuidResult>>(data, *cpuid_offset, 1)
                    .map_err(io::Error::from_raw_os_error)
                    .context("sgx_enarxcall deref")?
            };

            // Safety: we know we are on an SGX machine, which can do cpuid
            let cpuid_ret = unsafe { core::arch::x86_64::__cpuid_count(*leaf as _, *subleaf as _) };

            cpuid_buf.write(cpuid_ret);
            *ret = 0;
            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::GetSgxTargetInfo,
            argv: [target_info_offset, ..],
            ret,
        } => {
            let out_buf = unsafe {
                // Safety: `deref_slice` gives us a pointer to a byte slice, which does not have to be aligned.
                // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                // is a subslice of.
                &mut *deref_slice::<u8>(data, *target_info_offset, size_of::<TargetInfo>())
                    .map_err(io::Error::from_raw_os_error)
                    .context("sgx_enarxcall deref")?
            };

            let akid = get_attestation_key_id().context("error obtaining attestation key id")?;
            let pkeysize = get_key_size(akid.clone()).context("error obtaining key size")?;
            *ret = get_target_info(akid, pkeysize, out_buf).context("error getting target info")?;

            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::GetSgxQuote,
            argv: [report_offset, quote_offset, quote_len, ..],
            ret,
        } => {
            let report_buf = unsafe {
                // Safety: `deref_slice` gives us a pointer to a byte slice, which does not have to be aligned.
                // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                // is a subslice of.
                &mut *deref_slice::<u8>(data, *report_offset, size_of::<Report>())
                    .map_err(io::Error::from_raw_os_error)
                    .context("sgx_enarxcall deref")?
            };

            let quote_buf = unsafe {
                // Safety: `deref_slice` gives us a pointer to a byte slice, which does not have to be aligned.
                // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                // is a subslice of.
                &mut *deref_slice::<u8>(data, *quote_offset, *quote_len)
                    .map_err(io::Error::from_raw_os_error)
                    .context("sgx_enarxcall deref")?
            };

            let akid = get_attestation_key_id().context("error obtaining attestation key id")?;
            *ret = get_quote(report_buf, akid, quote_buf).context("error getting quote")?;

            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::GetSgxQuoteSize,
            ret,
            ..
        } => {
            let akid = get_attestation_key_id().context("error obtaining attestation key id")?;
            *ret = get_quote_size(akid).context("error getting quote size")?;

            Ok(None)
        }

        _ => return Ok(Some(Item::Enarxcall(enarxcall, data))),
    }
}

impl super::super::Thread for Thread {
    fn enter(&mut self, _gdblisten: &Option<String>) -> Result<Command> {
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

                inout("rdi") self.block.as_mut_ptr() => _,
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
                let block: Block = self.block.as_mut_slice().into();
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
                            sallyport::host::execute(sgx_enarxcall(enarxcall, data)?.into_iter())
                                .map_err(io::Error::from_raw_os_error)
                                .context("sallyport::host::execute")?;
                        }

                        // Catch exit and exit_group for a clean shutdown
                        Item::Syscall(syscall, ..)
                            if (syscall.num == libc::SYS_exit as usize
                                || syscall.num == libc::SYS_exit_group as usize) =>
                        {
                            if cfg!(feature = "dbg") {
                                dbg!(&syscall);
                            }
                            return Ok(Command::Exit(syscall.argv[0] as _));
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
