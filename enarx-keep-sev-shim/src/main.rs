// SPDX-License-Identifier: Apache-2.0

//! enarx-keep-sev-shim
//!
//! document

#![no_std]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
fn main() {}

mod asm;
mod no_std;

/// Defines the entry point function.
///
/// The function must have the signature `fn(&'static ())) -> !`.
///
/// This macro just creates a function named `_start_main`, which the assembler
/// stub will use as the entry point. The advantage of using this macro instead
/// of providing an own `_start_main` function is that the macro ensures that the
/// function and argument types are correct.
macro_rules! entry_point {
    ($path:path) => {
        #[allow(missing_docs)]
        #[export_name = "_start_main"]
        pub extern "C" fn __impl_start(boot_info: &'static ()) -> ! {
            // validate the signature of the program entry point
            let f: fn(&'static ()) -> ! = $path;
            f(boot_info)
        }
    };
}

entry_point!(kernel_main);

fn kernel_main(_boot_info: &'static ()) -> ! {
    use asm::{_enarx_asm_io_hello_world, _enarx_asm_ud2, hlt_loop};

    // Just some test code for now to trigger output
    unsafe { _enarx_asm_io_hello_world() };
    unsafe { _enarx_asm_ud2() };
    hlt_loop()
}
