// SPDX-License-Identifier: Apache-2.0

//! The SEV shim
//!
//! This crate contains the system/kernel that handles the syscalls (and cpuid instructions)
//! from the enclave code and might proxy them to the host.

#![no_std]
#![deny(clippy::all)]
#![deny(clippy::integer_arithmetic)]
#![deny(missing_docs)]
#![no_main]
#![feature(asm, naked_functions)]

extern crate compiler_builtins;
extern crate rcrt1;

pub mod addr;
pub mod asm;
pub mod frame_allocator;
pub mod gdt;
pub mod hostcall;
/// Shared components for the shim and the loader
pub mod hostlib;
pub mod no_std;
pub mod paging;
pub mod payload;
pub mod shim_stack;
#[macro_use]
pub mod print;
pub mod lazy;
pub mod random;
pub mod syscall;
pub mod usermode;

use crate::addr::ShimVirtAddr;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use primordial::Address;
use sallyport::Block;
use spinning::RwLock;

use crate::hostcall::HOST_CALL;
pub use hostlib::BootInfo;

static C_BIT_MASK: AtomicU64 = AtomicU64::new(0);

static BOOT_INFO: RwLock<Option<BootInfo>> =
    RwLock::<Option<BootInfo>>::const_new(spinning::RawRwLock::const_new(), None);

static SHIM_HOSTCALL_VIRT_ADDR: RwLock<Option<ShimVirtAddr<Block>>> =
    RwLock::<Option<ShimVirtAddr<Block>>>::const_new(spinning::RawRwLock::const_new(), None);

/// Get the SEV C-Bit mask
#[inline(always)]
pub fn get_cbit_mask() -> u64 {
    C_BIT_MASK.load(Ordering::Relaxed)
}

/// Switch the stack and jump to a function
///
/// # Safety
///
/// This function is unsafe, because the caller has to ensure a 16 byte
/// aligned usable stack.
#[allow(clippy::integer_arithmetic)]
pub unsafe fn switch_shim_stack(ip: extern "C" fn() -> !, sp: u64) -> ! {
    assert_eq!(sp % 16, 0);
    asm!(
        "mov rsp, {0}",
        "call {1}",
        in(reg) sp,
        in(reg) ip,
        options(noreturn, nomem)
    );
}

/// Defines the entry point function.
///
/// The function must have the signature `extern "C" fn() -> !`.
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
        pub unsafe extern "C" fn __impl_start(boot_info: *mut BootInfo, c_bit_mask: u64) -> ! {
            // validate the signature of the program entry point
            let f: extern "C" fn() -> ! = $path;

            C_BIT_MASK.store(c_bit_mask, Ordering::Relaxed);

            SHIM_HOSTCALL_VIRT_ADDR.write().replace(
                ShimVirtAddr::<Block>::try_from(Address::<u64, Block>::from(
                    boot_info as *mut Block,
                ))
                .unwrap(),
            );

            // make a local copy of boot_info, before the shared page gets overwritten
            BOOT_INFO.write().replace(boot_info.read_volatile());

            // Switch the stack to a guarded stack
            switch_shim_stack(f, gdt::INITIAL_STACK.pointer.as_u64())
        }
    };
}

entry_point!(shim_main);

/// The entry point for the shim
pub extern "C" fn shim_main() -> ! {
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
#[panic_handler]
#[allow(clippy::empty_loop)]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    use asm::_enarx_asm_triple_fault;

    static mut ALREADY_IN_PANIC: AtomicBool = AtomicBool::new(false);

    unsafe {
        if ALREADY_IN_PANIC
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            // panic info is useful
            HOST_CALL.force_unlock();
            eprintln!("{}", info);
            // FIXME: might want to have a custom panic hostcall
            hostcall::shim_exit(255);
        }
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() };
}
