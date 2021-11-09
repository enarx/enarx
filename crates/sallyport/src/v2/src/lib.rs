// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), no_std)]

/// Error type used within this crate.
pub type Error = libc::c_int;

/// Result type returned by functionality exposed by this crate.
pub type Result<T> = core::result::Result<T, Error>;
