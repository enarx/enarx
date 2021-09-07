// SPDX-License-Identifier: Apache-2.0

//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![no_std]
#![feature(asm)]
#![feature(naked_functions)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![no_main]

extern crate compiler_builtins;
extern crate rcrt1;

#[panic_handler]
#[cfg(not(test))]
#[allow(clippy::empty_loop)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// _Unwind_Resume is only needed in the `debug` profile
///
/// even though this project has `panic=abort`
/// it seems like the debug libc.rlib has some references
/// with unwinding
/// See also: https://github.com/rust-lang/rust/issues/47493
#[cfg(debug_assertions)]
#[no_mangle]
extern "C" fn _Unwind_Resume() {
    unimplemented!();
}

/// rust_eh_personality is only needed in the `debug` profile
///
/// even though this project has `panic=abort`
/// it seems like the debug libc.rlib has some references
/// with unwinding
/// See also: https://github.com/rust-lang/rust/issues/47493
#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {
    unimplemented!();
}

// ============== REAL CODE HERE ===============

mod enclave;
mod entry;
mod handler;
mod hostlib;

use hostlib::Layout;

use sallyport::Block;
use sgx::types::ssa::StateSaveArea;

const DEBUG: bool = false;

sallyport::declare_abi_version!();

#[repr(C)]
struct Context {
    layout: hostlib::Layout,
    ssa: [StateSaveArea],
}

#[repr(C)]
struct Input {
    cssa: usize,
    ctx: &'static mut Context,
}

#[allow(unreachable_code)]
extern "C" fn main(
    _rdi: usize,
    _rsi: usize,
    rdx: &mut Block,
    rcx: &mut Input,
    _r8: usize,
    _r9: usize,
) {
    match rcx.cssa {
        0 => entry::entry(&rcx.ctx.layout),
        1 => handler::Handler::handle(&mut rcx.ctx.ssa[0].gpr, rdx, rcx.ctx.layout.heap),
        n => handler::Handler::finish(&mut rcx.ctx.ssa[n - 1].gpr),
    }
}
