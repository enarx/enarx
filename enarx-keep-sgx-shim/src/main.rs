// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![cfg_attr(not(test), no_main)]
#![deny(clippy::all)]

#[cfg(not(test))]
#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
fn main() {}

// ============== REAL CODE HERE ===============

pub mod libc;

use linux_syscall::x86_64::SysCall;
use sgx_types::{ssa::StateSaveArea, tcs::Tcs};

pub enum Context {}

extern "C" {
    #[no_mangle]
    fn syscall(
        rdi: u64,
        rsi: u64,
        rdx: u64,
        aex: &mut StateSaveArea,
        r8: u64,
        r9: u64,
        r10: u64,
        rax: SysCall,
        ctx: &Context,
    ) -> u64;
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn enter(
    _rdi: u64,
    _rsi: u64,
    _rdx: u64,
    _tcs: &Tcs,
    _r8: u64,
    _r9: u64,
    aex: Option<&mut StateSaveArea>,
    ctx: &Context,
) {
    if let Some(aex) = aex {
        match core::slice::from_raw_parts(aex.gpr.rip as *const u8, 2) {
            // syscall
            [0x0f, 0x05] => {
                aex.gpr.rip += 2;
                aex.gpr.rax = match aex.gpr.rax.into() {
                    rax @ SysCall::EXIT => syscall(aex.gpr.rdi, 0, 0, aex, 0, 0, 0, rax, ctx),
                    rax @ SysCall::GETUID => syscall(0, 0, 0, aex, 0, 0, 0, rax, ctx),
                    _ => syscall(8, 0, 0, aex, 0, 0, 0, SysCall::EXIT, ctx),
                };
            }

            _ => {
                syscall(9, 0, 0, aex, 0, 0, 0, SysCall::EXIT, ctx);
            }
        };
    } else {
        extern "C" {
            fn do_syscall(
                rdi: u64,
                rsi: u64,
                rdx: u64,
                r10: u64,
                r8: u64,
                r9: u64,
                rax: SysCall,
            ) -> u64;
        }

        let uid = do_syscall(0, 0, 0, 0, 0, 0, SysCall::GETUID);
        do_syscall(uid / 100, 0, 0, 0, 0, 0, SysCall::EXIT);
    }
}
