// SPDX-License-Identifier: Apache-2.0

//! errno type and constants for various architectures
#![no_std]
#![deny(clippy::all)]

// ErrNo values generated with:
//
// ```
// bindgen /usr/include/errno.h \
//   | sed -rn 's|pub const (E[A-Z0-9_]*): u32 = ([0-9]+);|\1 = \2,|p' \
//   | sort -g -t= -k2
// ```

/// x86 errno
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::ErrNo;
