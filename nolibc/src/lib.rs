// SPDX-License-Identifier: Apache-2.0

//! errno type and constants for various architectures
//!
//! TODO: this crate is temporary:
//! https://github.com/enarx/enarx/issues/364

#![no_std]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![allow(missing_docs)]

/// x86 errno
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
