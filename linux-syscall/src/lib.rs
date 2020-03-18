// SPDX-License-Identifier: Apache-2.0

//! syscall type and constants for various architectures
#![no_std]
#![deny(clippy::all)]

// SysCall values generated with:
//
// ```
// bindgen /usr/include/sys/syscall.h \
//   | sed -rn 's|pub const SYS_([a-z][a-z0-9_]*): u32 = ([0-9]+);|\1 = \2,|p' \
//   | tr [:lower:] [:upper:] \
//   | sort -g -t= -k2
// ```

/// x86_64 syscalls
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::SysCall;
