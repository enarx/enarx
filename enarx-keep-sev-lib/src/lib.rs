// SPDX-License-Identifier: Apache-2.0

//! This crate represents the hypervisor-microkernel boundary. It contains a number
//! of a shared structures to help facilitate communication between the two entities.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![no_std]

pub mod proxy;
