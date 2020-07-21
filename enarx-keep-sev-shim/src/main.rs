// SPDX-License-Identifier: Apache-2.0

//! The SEV shim
//!
//! This crate contains the system/kernel that handles the syscalls (and cpuid instructions)
//! from the enclave code and might proxy them to the host.

#![no_std]
#![deny(clippy::all)]
#![deny(clippy::integer_arithmetic)]
#![deny(missing_docs)]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
fn main() {}

pub mod addr;
pub mod asm;
pub mod gdt;
pub mod hostcall;
pub mod no_std;
pub mod print;
pub mod syscall;
pub mod usermode;

use addr::ShimVirtAddr;
use core::convert::TryFrom;
use enarx_keep_sev_shim::BootInfo;
use hostcall::HostCall;
use memory::{Address, Page};
use x86_64::VirtAddr;

/// Defines the entry point function.
///
/// The function must have the signature `fn(*mut BootInfo) -> !`.
///
/// This macro just creates a function named `_start_main`, which the assembler
/// stub will use as the entry point. The advantage of using this macro instead
/// of providing an own `_start_main` function is that the macro ensures that the
/// function and argument types are correct.
macro_rules! entry_point {
    ($path:path) => {
        #[doc(hidden)]
        #[export_name = "_start_main"]
        pub extern "C" fn __impl_start(boot_info: *mut BootInfo) -> ! {
            // validate the signature of the program entry point
            let f: fn(*mut BootInfo) -> ! = $path;
            f(boot_info)
        }
    };
}

entry_point!(shim_main);

/// FIXME: will be replaced by a dynamically allocated stack with safe guards
pub static mut LEVEL_0_STACK: [Page; 5] = [Page::zeroed(); 5];

/// The entry point for the shim
pub fn shim_main(boot_info: *mut BootInfo) -> ! {
    HostCall::init(ShimVirtAddr::try_from(Address::from(boot_info).try_cast().unwrap()).unwrap());

    unsafe {
        gdt::init(VirtAddr::from_ptr(&LEVEL_0_STACK));
    }
    eprintln!("Hello World!");

    hostcall::shim_exit(0);
}

/// The panic function
///
/// Called, whenever somethings panics.
///
/// Reverts to a triple fault, which causes a `#VMEXIT` and a KVM shutdown,
/// if it can't print the panic and exit normally with an error code.
#[cfg(not(test))]
#[panic_handler]
#[allow(clippy::empty_loop)]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    use asm::_enarx_asm_triple_fault;
    use core::sync::atomic::{AtomicBool, Ordering};

    static mut ALREADY_IN_PANIC: AtomicBool = AtomicBool::new(false);

    unsafe {
        if !ALREADY_IN_PANIC.swap(true, Ordering::AcqRel) {
            eprintln!("{}", info);
            // FIXME: might want to have a custom panic hostcall
            hostcall::shim_exit(255);
        }
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() };
}
