// SPDX-License-Identifier: Apache-2.0

//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![no_std]
#![cfg_attr(not(test), no_main)]
#![deny(clippy::all)]
#![deny(missing_docs)]

extern crate rcrt1;

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

macro_rules! debug {
    ($dst:expr, $($arg:tt)*) => {
        #[allow(unused_must_use)] {
            use core::fmt::Write;
            write!($dst, $($arg)*);
        }
    };
}

macro_rules! debugln {
    ($dst:expr) => { debugln!($dst,) };
    ($dst:expr, $($arg:tt)*) => {
        #[allow(unused_must_use)] {
            use core::fmt::Write;
            writeln!($dst, $($arg)*);
        }
    };
}

#[cfg(not(test))]
mod entry;
mod event;
mod handler;
mod heap;

use shim_sgx::Layout;
