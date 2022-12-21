// SPDX-License-Identifier: Apache-2.0

//! The SEV shim
//!
//! Contains the startup code and the main function.
#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![feature(asm_const)]
#![cfg_attr(coverage, feature(no_coverage))]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
pub mod start;

#[cfg(not(target_os = "none"))]
pub fn main() {}
