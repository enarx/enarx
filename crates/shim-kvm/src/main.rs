// SPDX-License-Identifier: Apache-2.0

//! The SEV-SNP and KVM shim executable

#![feature(asm_const)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![cfg_attr(coverage, feature(no_coverage))]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(all(
    target_arch = "x86_64",
    target_vendor = "unknown",
    target_os = "none",
    target_env = ""
))]
pub mod start;

/// A fake main function
///
/// This is used when compiling the shim for the host.
/// Look into the [start] module for the real main function.
#[cfg(not(all(
    target_arch = "x86_64",
    target_vendor = "unknown",
    target_os = "none",
    target_env = ""
)))]
pub fn main() {}
