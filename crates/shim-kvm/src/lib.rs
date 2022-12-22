// SPDX-License-Identifier: Apache-2.0
#![cfg(any(
    all(test, target_arch = "x86_64", target_os = "linux"),
    target_vendor = "unknown"
))]
//! The SEV shim
//!
//! This crate contains the system/kernel that handles the syscalls (and cpuid instructions)
//! from the enclave code and might proxy them to the host.

#![cfg_attr(not(test), no_std)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![feature(asm_const, c_size_t)]
#![warn(rust_2018_idioms)]
#![cfg_attr(coverage, feature(no_coverage))]

use goblin::elf::header::header64::Header;
use nbytes::bytes;
use primordial::Page as Page4KiB;
use shared::no_std::cpuid_page::CpuidPage;
use x86_64::VirtAddr;

#[macro_use]
pub mod print;
pub mod addr;
pub mod allocator;
pub mod debug;
pub mod exec;
pub mod gdb;
pub mod gdt;
pub mod hostcall;
pub mod interrupts;
pub mod pagetables;
pub mod paging;
pub mod random;
pub mod shim_stack;
pub mod snp;
pub mod spin;
pub mod sse;
pub mod syscall;
pub mod usermode;

extern "C" {
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
}

/// The virtual address of the main kernel stack
pub const SHIM_STACK_START: u64 = 0xFFFF_FF48_4800_0000;

/// The size of the main kernel stack
#[allow(clippy::integer_arithmetic)]
pub const SHIM_STACK_SIZE: u64 = bytes![2; MiB];

/// The virtual address of the exception kernel stacks
pub const SHIM_EX_STACK_START: u64 = 0xFFFF_FF48_F000_0000;

/// The size of the main kernel stack for exceptions
#[allow(clippy::integer_arithmetic)]
pub const SHIM_EX_STACK_SIZE: u64 = {
    if cfg!(feature = "gdb") {
        bytes![2; MiB]
    } else {
        bytes![32; KiB]
    }
};

/// Exec virtual address, where the elf binary is mapped to, plus a random offset
const EXEC_ELF_VIRT_ADDR_BASE: VirtAddr = VirtAddr::new_truncate(0x7f00_0000_0000);

/// The first brk virtual address the exec gets, plus a random offset
const EXEC_BRK_VIRT_ADDR_BASE: VirtAddr = VirtAddr::new_truncate(0x5555_0000_0000);

/// Exec stack virtual address
const EXEC_STACK_VIRT_ADDR_BASE: VirtAddr = VirtAddr::new_truncate(0x7ff0_0000_0000);

/// Initial exec stack size
#[allow(clippy::integer_arithmetic)]
const EXEC_STACK_SIZE: u64 = bytes![2; MiB];
