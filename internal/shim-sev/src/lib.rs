// SPDX-License-Identifier: Apache-2.0

//! The SEV shim
//!
//! This crate contains the system/kernel that handles the syscalls (and cpuid instructions)
//! from the enclave code and might proxy them to the host.

#![cfg_attr(not(test), no_std)]
#![deny(clippy::all)]
#![cfg_attr(not(test), deny(clippy::integer_arithmetic))]
#![deny(missing_docs)]
#![feature(asm, asm_const, asm_sym, naked_functions)]

use crate::snp::cpuid_page::CpuidPage;
use crate::snp::ghcb::Ghcb;
use crate::snp::secrets_page::SnpSecretsPage;

use goblin::elf::header::header64::Header;
use primordial::Page as Page4KiB;
use sallyport::Block;

#[macro_use]
pub mod testaso;

#[macro_use]
pub mod print;

pub mod addr;
pub mod allocator;
pub mod debug;
pub mod exec;
pub mod gdb;
pub mod gdt;
pub mod hostcall;
pub mod hostmap;
pub mod idt;
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
