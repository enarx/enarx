// SPDX-License-Identifier: Apache-2.0

//! A crate to share code between the Enarx components

#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![allow(unsafe_op_in_unsafe_fn)]
#![cfg_attr(target_os = "none", no_std)]

pub mod no_std;

#[cfg(not(target_os = "none"))]
pub mod std;
