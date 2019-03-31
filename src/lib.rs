#![allow(unknown_lints)]
#![warn(clippy::all)]

#[cfg(feature = "fwapi")]
extern crate errno;

pub mod certs;

#[cfg(feature = "fwapi")]
pub mod fwapi;
