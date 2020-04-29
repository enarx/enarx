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

mod elf;
mod entry;
mod event;
mod handler;
mod heap;
mod libc;

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
