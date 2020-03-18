// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![cfg_attr(not(test), no_main)]
#![deny(clippy::all)]
// TODO: https://github.com/enarx/enarx/issues/343
#![deny(missing_docs)]
#![allow(missing_docs)]

#[cfg(not(test))]
#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
fn main() {}

// ============== REAL CODE HERE ===============

mod handler;

use handler::Handler;
use nolibc::x86_64::syscall::Number as SysCall;
use sgx_types::{ssa::StateSaveArea, tcs::Tcs};

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn entry(
    _rdi: u64,
    _rsi: u64,
    _rdx: u64,
    _tcs: &Tcs,
    _r8: u64,
    _r9: u64,
) -> ! {
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

    const MSG: &str = "Γειά σου Κόσμε!\n";

    do_syscall(
        1,
        MSG.as_ptr() as _,
        MSG.len() as _,
        0,
        0,
        0,
        SysCall::WRITE,
    );
    do_syscall(0, 0, 0, 0, 0, 0, SysCall::EXIT);
    panic!()
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn event(
    _rdi: u64,
    _rsi: u64,
    _rdx: u64,
    tcs: &Tcs,
    _r8: u64,
    _r9: u64,
    aex: &mut StateSaveArea,
    ctx: &handler::Context,
) {
    match core::slice::from_raw_parts(aex.gpr.rip as *const u8, 2) {
        // syscall
        [0x0f, 0x05] => {
            let syscall = aex.gpr.rax.into();
            let mut h = Handler::new(tcs, aex, ctx);

            aex.gpr.rax = match syscall {
                SysCall::READ => h.read(),
                SysCall::WRITE => h.write(),
                SysCall::GETUID => h.getuid(),
                SysCall::EXIT => h.exit(None),
                _ => h.exit(254),
            };

            aex.gpr.rip += 2;
        }

        _ => Handler::new(tcs, aex, ctx).exit(255),
    };
}
