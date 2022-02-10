// SPDX-License-Identifier: Apache-2.0

//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![cfg_attr(not(test), no_std)]
#![allow(incomplete_features)]
#![feature(asm_const, asm_sym)]
#![feature(generic_const_exprs)]
#![feature(naked_functions)]
#![feature(const_mut_refs)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

#[macro_use]
pub mod testaso;

pub mod entry;
pub mod handler;
pub mod heap;
pub mod uarch;

use sgx::parameters::{Attributes, Features, MiscSelect, Xfrm};

const DEBUG: bool = cfg!(feature = "dbg");

/// FIXME: doc
pub const ENCL_SIZE_BITS: u8 = 31;
/// FIXME: doc
pub const ENCL_SIZE: usize = 1 << ENCL_SIZE_BITS;

const XFRM: Xfrm = Xfrm::from_bits_truncate(
    Xfrm::X87.bits()
        | Xfrm::SSE.bits()
        | Xfrm::AVX.bits()
        | Xfrm::OPMASK.bits()
        | Xfrm::ZMM_HI256.bits()
        | Xfrm::HI16_ZMM.bits(),
);

/// Default enclave CPU attributes
pub const ATTR: Attributes = Attributes::new(Features::MODE64BIT, XFRM);

/// Default miscelaneous SSA data selector
pub const MISC: MiscSelect = {
    if cfg!(dbg) {
        MiscSelect::EXINFO
    } else {
        MiscSelect::empty()
    }
};

// NOTE: You MUST take the address of these symbols for them to work!
extern "C" {
    /// Extern
    pub static ENARX_EXEC_START: u8;
    /// Extern
    pub static ENARX_EXEC_END: u8;
}
