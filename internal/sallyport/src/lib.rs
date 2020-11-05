// SPDX-License-Identifier: Apache-2.0

//! This crate represents the hypervisor-microkernel boundary. It contains a number
//! of a shared structures to help facilitate communication between the two entities.

#![feature(asm)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![cfg_attr(not(test), no_std)]

include!("../../../src/sallyport/mod.rs");
