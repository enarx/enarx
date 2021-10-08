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
pub mod attestation;
pub mod debug;
pub mod gdt;
pub mod hostcall;
pub mod hostmap;
pub mod idt;
pub mod interrupts;
pub mod no_std;
pub mod pagetables;
pub mod paging;
pub mod payload;
pub mod random;
pub mod shim_stack;
pub mod snp;
pub mod spin;
pub mod sse;
mod start;
pub mod syscall;
pub mod usermode;

use crate::debug::print_stack_trace;
use crate::pagetables::unmap_identity;
use crate::print::{enable_printing, is_printing_enabled};
use crate::snp::cpuid_page::CpuidPage;
use crate::snp::ghcb::Ghcb;
use crate::snp::secrets_page::SnpSecretsPage;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use goblin::elf::header::header64::Header;
use noted::noted;
use primordial::Page as Page4KiB;
use sallyport::{elf::note, Block, REQUIRES};

noted! {
    static NOTE_ENARX_SALLYPORT<note::NAME, note::REQUIRES, [u8; REQUIRES.len()]> = REQUIRES;
}

static C_BIT_MASK: AtomicU64 = AtomicU64::new(0);

static PAYLOAD_READY: AtomicBool = AtomicBool::new(false);

extern "C" {
    /// Extern
    pub static mut _ENARX_SALLYPORT_START: Block;
    /// Extern
    pub static _ENARX_SALLYPORT_END: Page4KiB;
    /// Extern
    pub static _ENARX_MEM_START: Page4KiB;
    /// Extern
    pub static _ENARX_SHIM_START: Page4KiB;
    /// Extern
    pub static _ENARX_EXEC_START: Header;
    /// Extern
    pub static _ENARX_EXEC_END: Page4KiB;
    /// Extern
    pub static _ENARX_CPUID: CpuidPage;
    /// Extern
    pub static mut _ENARX_GHCB: Ghcb;
    /// Extern
    pub static mut _ENARX_SECRETS: SnpSecretsPage;
}

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

    unmap_identity();

    // Everything setup, so print works
    enable_printing();

    // Switch the stack to a guarded stack
    switch_shim_stack(shim_main, gdt::INITIAL_STACK.pointer.as_u64())
}

/// The entry point for the shim
extern "C" fn shim_main() -> ! {
    unsafe { gdt::init() };
    sse::init_sse();
    interrupts::init();

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
    use debug::_enarx_asm_triple_fault;

    static mut ALREADY_IN_PANIC: AtomicBool = AtomicBool::new(false);

    // Don't print anything, if the FRAME_ALLOCATOR is not yet initialized
    unsafe {
        if is_printing_enabled()
            && ALREADY_IN_PANIC
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            print::_eprint(format_args!("{}\n", info));
            print_stack_trace();
            // FIXME: might want to have a custom panic hostcall
            hostcall::shim_exit(255);
        }
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() }
}
