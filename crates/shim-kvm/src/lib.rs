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
use primordial::Page as Page4KiB;
use shared::no_std::cpuid_page::CpuidPage;

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
