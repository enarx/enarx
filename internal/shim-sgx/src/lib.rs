// SPDX-License-Identifier: Apache-2.0

//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![cfg_attr(not(test), no_std)]
#![feature(asm)]
#![feature(naked_functions)]
#![deny(clippy::all)]
#![deny(missing_docs)]

pub mod entry;
pub mod handler;
pub mod heap;

use sgx::parameters::{Attributes, Features, Xfrm};

const DEBUG: bool = cfg!(feature = "dbg");

/// FIXME: doc
pub const ENCL_SIZE_BITS: u8 = 31;
/// FIXME: doc
pub const ENCL_SIZE: usize = 1 << ENCL_SIZE_BITS;

const XFRM: Xfrm = Xfrm::from_bits_truncate(Xfrm::X87.bits() | Xfrm::SSE.bits());
/// FIXME: doc
pub const ATTR: Attributes = Attributes::new(Features::MODE64BIT, XFRM);

// NOTE: You MUST take the address of these symbols for them to work!
extern "C" {
    /// Extern
    pub static ENARX_EXEC_START: u8;
    /// Extern
    pub static ENARX_EXEC_END: u8;
    /// Extern
    pub static ENARX_HEAP_START: u8;
    /// Extern
    pub static ENARX_HEAP_END: u8;
}
