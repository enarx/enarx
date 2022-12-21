// SPDX-License-Identifier: Apache-2.0

//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![feature(asm_const)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
pub fn main() {}

#[cfg(target_os = "none")]
pub mod start;
