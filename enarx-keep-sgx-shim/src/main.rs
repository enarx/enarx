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

mod entry;
mod event;
mod handler;
mod libc;
