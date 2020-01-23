// SPDX-License-Identifier: Apache-2.0

//! syscall type and constants for various architectures
#![no_std]
#![deny(clippy::all)]

/// x86_64 syscalls
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
