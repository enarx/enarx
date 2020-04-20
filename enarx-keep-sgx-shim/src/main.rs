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

/// _Unwind_Resume is only needed in the `debug` profile
///
/// even though this project has `panic=abort`
/// it seems like the debug libc.rlib has some references
/// with unwinding
/// See also: https://github.com/rust-lang/rust/issues/47493
#[cfg(not(test))]
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
#[cfg(not(test))]
#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {
    unimplemented!();
}

#[cfg(test)]
fn main() {}

// ============== REAL CODE HERE ===============

mod elf;
mod entry;
mod event;
mod handler;
mod heap;

use span::Line;

// NOTE: this must be kept in sync with enarx-keep-sgx
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Layout {
    pub enclave: Line<u64>,

    pub prefix: Line<u64>,
    pub code: Line<u64>,
    pub heap: Line<u64>,
    pub stack: Line<u64>,
    pub shim: Line<u64>,
}
