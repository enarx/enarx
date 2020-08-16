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
#![feature(asm, naked_functions)]
// FIXME: needed for memoffset
#![feature(
    raw_ref_macros,
    ptr_offset_from,
    const_raw_ptr_deref,
    const_ptr_offset_from,
    const_maybe_uninit_as_ptr
)]

#[cfg(test)]
fn main() {}

#[macro_use]
extern crate lazy_static;

extern crate rcrt1;

pub mod addr;
pub mod asm;
pub mod frame_allocator;
pub mod gdt;
pub mod hostcall;
pub mod no_std;
pub mod paging;
pub mod payload;
pub mod shim_stack;
#[macro_use]
pub mod print;
pub mod random;
pub mod syscall;
pub mod usermode;

use core::ops::Deref;
use shim_sev::BootInfo;
use spinning::RwLock;
use x86_64::VirtAddr;

static BOOT_INFO: RwLock<Option<BootInfo>> =
    RwLock::<Option<BootInfo>>::const_new(spinning::RawRwLock::const_new(), None);

static SHIM_HOSTCALL_VIRT_ADDR: RwLock<Option<VirtAddr>> =
    RwLock::<Option<VirtAddr>>::const_new(spinning::RawRwLock::const_new(), None);

/// Defines the entry point function.
///
/// The function must have the signature `fn(*mut BootInfo) -> !`.
///
/// This macro just creates a function named `_start_main`, which the assembler
/// stub will use as the entry point. The advantage of using this macro instead
/// of providing an own `_start_main` function is that the macro ensures that the
/// function and argument types are correct and that the global variables, which
/// are needed later on, are initialized.
macro_rules! entry_point {
    ($path:path) => {
        #[doc(hidden)]
        #[export_name = "_start_main"]
        pub unsafe extern "C" fn __impl_start(boot_info: *mut BootInfo) -> ! {
            // validate the signature of the program entry point
            let f: fn() -> ! = $path;

            SHIM_HOSTCALL_VIRT_ADDR
                .write()
                .replace(VirtAddr::from_ptr(boot_info));

            // make a local copy of boot_info, before the shared page gets overwritten
            let boot_info = boot_info.read_volatile();
            BOOT_INFO.write().replace(boot_info);

            f()
        }
    };
}

entry_point!(shim_main);

/// The entry point for the shim
pub fn shim_main() -> ! {
    dbg!(BOOT_INFO.read().deref());

    unsafe {
        gdt::init();
    }

    payload::execute_payload()
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
