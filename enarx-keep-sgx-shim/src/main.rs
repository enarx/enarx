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

use sgx_types::ssa::StateSaveArea;

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn event(aex: &mut StateSaveArea) {
    aex.gpr.rip += 2; // Skip the UD2 instruction
}
