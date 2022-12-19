// SPDX-License-Identifier: Apache-2.0
#![cfg(any(
    all(test, target_arch = "x86_64", target_os = "linux"),
    target_vendor = "unknown"
))]
//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![cfg_attr(not(test), no_std)]
#![feature(c_size_t)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod entry;
pub mod handler;
pub mod heap;
pub mod thread;

use primordial::Page;
use sgx::parameters::{Attributes, Features, MiscSelect, Xfrm};
use sgx::ssa::StateSaveArea;

const DEBUG: bool = cfg!(feature = "dbg");

/// Number of available slots for SSA frames.
pub const NUM_SSA: usize = 4;

/// Stack size of the CSSA = 0
/// as defined in the linker script `layout.ld`
pub const CSSA_0_STACK_SIZE: usize = 0x800000 - Page::SIZE; // 8MB - TCB

/// Stack size of the CSSA > 0
/// as defined in the linker script `layout.ld`
pub const CSSA_1_PLUS_STACK_SIZE: usize =
    0x800000 - Page::SIZE - NUM_SSA * core::mem::size_of::<StateSaveArea>(); // 8MB - TCS - SSA

/// Defines the size of the enclave address space
///
/// This is now 16GB, enough for wasmtime to allocate 8GB of memory for the wasm payload
/// and still have some memory left for the shim and the stack.
pub const ENCL_SIZE_BITS: u8 = 34;
/// Defines the size of the enclave address space
pub const ENCL_SIZE: usize = 1 << ENCL_SIZE_BITS;

const XFRM: Xfrm = Xfrm::from_bits_truncate(
    Xfrm::X87.bits()
        | Xfrm::SSE.bits()
        | Xfrm::AVX.bits()
        | Xfrm::OPMASK.bits()
        | Xfrm::ZMM_HI256.bits()
        | Xfrm::HI16_ZMM.bits(),
);

const FEATURES: Features = Features::MODE64BIT;

#[cfg(any(features = "dbg", features = "gdb", features = "bench"))]
const KEEP_FEATURES: Features =
    Features::from_bits_truncate(FEATURES.bits() | Features::DEBUG.bits());

#[cfg(not(any(features = "dbg", features = "gdb", features = "bench")))]
const KEEP_FEATURES: Features = FEATURES;

/// Default enclave CPU attributes
pub const ATTR: Attributes = Attributes::new(KEEP_FEATURES, XFRM);

/// Default miscellaneous SSA data selector
pub const MISC: MiscSelect = MiscSelect::EXINFO;

/// The size of the sallyport block
pub const BLOCK_SIZE: usize = 69632;

// NOTE: You MUST take the address of these symbols for them to work!
extern "C" {
    /// Extern
    pub static ENARX_SHIM_ADDRESS: u8;
    /// Extern
    pub static ENARX_EXEC_START: u8;
    /// Extern
    pub static ENARX_EXEC_END: u8;
}

/// Get the Shim's base address used to check ranges and calculate offsets.
#[inline]
pub fn shim_address() -> usize {
    unsafe { &ENARX_SHIM_ADDRESS as *const _ as usize }
}
