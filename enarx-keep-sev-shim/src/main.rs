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
pub mod frame_allocator;
pub mod gdt;
pub mod hostcall;
pub mod no_std;
pub mod paging;
pub mod shim_stack;
#[macro_use]
pub mod singleton;
#[macro_use]
pub mod print;
pub mod syscall;
pub mod usermode;

use crate::addr::ShimVirtAddr;
use crate::frame_allocator::ShimFrameAllocatorRWLock;
use crate::hostcall::HostCallMutex;
use crate::paging::ShimPageTableRWLock;
use core::convert::TryFrom;
use enarx_keep_sev_shim::BootInfo;
use memory::Address;
use shim_stack::init_shim_stack;

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
        pub unsafe extern "C" fn __impl_start(boot_info: *mut BootInfo) -> ! {
            // validate the signature of the program entry point
            let f: unsafe fn(*mut BootInfo) -> ! = $path;
            f(boot_info)
        }
    };
}

entry_point!(shim_main);

/// The entry point for the shim
///
/// # Safety
///
/// Unsafe, because the caller has to ensure the `BootInfo` pointer is valid
pub unsafe fn shim_main(boot_info: *mut BootInfo) -> ! {
    let boot_info_addr = Address::from(boot_info).try_cast().unwrap();

    // make a local copy of boot_info, before the shared page gets overwritten
    let boot_info = boot_info.read_volatile();

    let shared_page = ShimVirtAddr::try_from(boot_info_addr).unwrap();

    // Warning: No println!()/eprintln!() before this point!
    HostCallMutex::init(shared_page);

    dbg!(boot_info);

    eprintln!("Hello World!");

    ShimFrameAllocatorRWLock::init(&boot_info);
    ShimPageTableRWLock::init();

    let stack_ptr = init_shim_stack();

    gdt::init(stack_ptr);

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
        if ALREADY_IN_PANIC
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            eprintln!("{}", info);
            // FIXME: might want to have a custom panic hostcall
            hostcall::shim_exit(255);
        }
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() };
}
