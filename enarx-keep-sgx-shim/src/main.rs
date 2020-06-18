// SPDX-License-Identifier: Apache-2.0

//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![no_std]
#![cfg_attr(not(test), no_main)]
#![deny(clippy::all)]
#![deny(missing_docs)]

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

mod elf;
mod entry;
mod event;
mod handler;
mod heap;

use span::Line;

/// The enclave layout
/// NOTE: this must be kept in sync with enarx-keep-sgx
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The boundaries of the enclave.
    pub enclave: Line<u64>,

    /// The boundaries of the prefix.
    pub prefix: Line<u64>,

    /// The boundaries of the code.
    pub code: Line<u64>,

    /// The boundaries of the heap.
    pub heap: Line<u64>,

    /// The boundaries of the stack.
    pub stack: Line<u64>,

    /// The boundaries of the shim.
    pub shim: Line<u64>,
}
