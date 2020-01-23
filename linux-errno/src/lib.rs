// SPDX-License-Identifier: Apache-2.0

//! errno type and constants for various architectures
#![no_std]
#![deny(clippy::all)]

/// x86 errno
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
