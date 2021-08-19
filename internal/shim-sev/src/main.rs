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

#[macro_use]
pub mod print;

pub mod addr;
pub mod allocator;
pub mod asm;
pub mod attestation;
pub mod gdt;
pub mod hostcall;
pub mod hostmap;
pub mod no_std;
pub mod pagetables;
pub mod paging;
pub mod payload;
pub mod random;
pub mod shim_stack;
pub mod spin;
mod start;
pub mod syscall;
pub mod usermode;

use crate::attestation::SevSecret;
use crate::pagetables::switch_sallyport_to_unencrypted;
use crate::paging::SHIM_PAGETABLE;
use crate::payload::PAYLOAD_VIRT_ADDR;
use crate::print::{enable_printing, is_printing_enabled};
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use goblin::elf::header::header64::Header;
use primordial::Page as Page4KiB;
use sallyport::Block;
use spinning::RwLock;
use x86_64::structures::paging::Translate;
use x86_64::VirtAddr;

static C_BIT_MASK: AtomicU64 = AtomicU64::new(0);

static SEV_SECRET: RwLock<Option<SevSecret>> =
    RwLock::<Option<SevSecret>>::const_new(spinning::RawRwLock::const_new(), None);

static PAYLOAD_READY: AtomicBool = AtomicBool::new(false);

extern "C" {
    /// Extern
    pub static _ENARX_SALLYPORT_START: Block;
    /// Extern
    pub static _ENARX_SALLYPORT_END: Page4KiB;
    /// Extern
    pub static _ENARX_MEM_START: Page4KiB;
    /// Extern
    pub static _ENARX_SHIM_START: Page4KiB;
    /// Extern
    pub static _ENARX_CODE_START: Header;
    /// Extern
    pub static _ENARX_CODE_END: Page4KiB;
}

sallyport::declare_abi_version!();

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
    asm!("
        mov rsp, {SP}
        sub rsp, 8
        push rbp
        call {IP}
        ",
        SP = in(reg) sp,
        IP = in(reg) ip,
        options(noreturn, nomem)
    )
}

/// Defines the entry point function.
///
/// # Safety
/// Do not call from Rust.
pub unsafe extern "sysv64" fn _start_main(c_bit_mask: u64) -> ! {
    C_BIT_MASK.store(c_bit_mask, Ordering::Relaxed);

    // make a local copy of boot_info, before the shared page gets overwritten
    SEV_SECRET
        .write()
        .replace((&_ENARX_SALLYPORT_START as *const _ as *const SevSecret).read());

    switch_sallyport_to_unencrypted(c_bit_mask);

    // Everything setup, so print works
    enable_printing();

    // Switch the stack to a guarded stack
    switch_shim_stack(shim_main, gdt::INITIAL_STACK.pointer.as_u64())
}

/// The entry point for the shim
extern "C" fn shim_main() -> ! {
    unsafe { gdt::init() };
    payload::execute_payload()
}

/// The panic function
///
/// Called, whenever somethings panics.
///
/// Reverts to a triple fault, which causes a `#VMEXIT` and a KVM shutdown,
/// if it can't print the panic and exit normally with an error code.
#[panic_handler]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    use asm::_enarx_asm_triple_fault;

    static mut ALREADY_IN_PANIC: AtomicBool = AtomicBool::new(false);

    // Don't print anything, if the FRAME_ALLOCATOR is not yet initialized
    unsafe {
        if is_printing_enabled()
            && ALREADY_IN_PANIC
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            print::_eprint(format_args!("{}\n", info));
            stack_trace();
            // FIXME: might want to have a custom panic hostcall
            hostcall::shim_exit(255);
        }
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() }
}

#[inline(never)]
unsafe fn stack_trace() {
    let mut rbp: usize;

    asm!("mov {}, rbp", out(reg) rbp);

    print::_eprint(format_args!("TRACE:\n"));

    if SHIM_PAGETABLE.try_read().is_none() {
        SHIM_PAGETABLE.force_unlock_write()
    }

    let shim_offset = crate::addr::SHIM_VIRT_OFFSET as usize;

    let active_table = SHIM_PAGETABLE.read();

    //Maximum 64 frames
    for _frame in 0..64 {
        if let Some(rip_rbp) = rbp.checked_add(size_of::<usize>() as _) {
            if active_table
                .translate_addr(VirtAddr::new(rbp as _))
                .is_some()
                && active_table
                    .translate_addr(VirtAddr::new(rip_rbp as _))
                    .is_some()
            {
                let rip = *(rip_rbp as *const usize);
                if let Some(rip) = rip.checked_sub(1) {
                    if rip == 0 {
                        break;
                    }

                    if let Some(rip) = rip.checked_sub(shim_offset) {
                        print::_eprint(format_args!("  0x{:>016x}\n", rip));
                        rbp = *(rbp as *const usize);
                    } else if PAYLOAD_READY.load(Ordering::Relaxed) {
                        if let Some(rip) = rip.checked_sub(PAYLOAD_VIRT_ADDR.read().as_u64() as _) {
                            print::_eprint(format_args!("P 0x{:>016x}\n", rip));
                            rbp = *(rbp as *const usize);
                        } else {
                            break;
                        }
                    }
                } else {
                    // RIP zero
                    break;
                }
            } else {
                // RBP NOT MAPPED
                break;
            }
        } else {
            // RBP OVERFLOW
            break;
        }
    }
}
