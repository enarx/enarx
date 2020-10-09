// SPDX-License-Identifier: Apache-2.0

//! This crate represents the hypervisor-microkernel boundary. It contains a number
//! of a shared structures to help facilitate communication between the two entities.

#![feature(asm)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![cfg_attr(not(test), no_std)]

//! The `proxy` module contains structures used to facilitate communication between
//! the microkernel and the hypervisor. This is referred to as "proxying" in the
//! project literature. This is a very thin and low-level layer that is meant to
//! be as transparent as possible.

include!("../../../src/sallyport/mod.rs");
