// SPDX-License-Identifier: Apache-2.0

//! errno type and constants for various architectures
//!
//! TODO: this crate is temporary:
//! https://github.com/enarx/enarx/issues/364

#![no_std]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![allow(missing_docs)]

/// x86 errno
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

enumerate::enumerate! {
    #[derive(Copy, Clone)]
    pub enum ArchPrctlTask: u64 {
        ArchSetGs = 0x1001,
        ArchSetFs = 0x1002,
        ArchGetFs = 0x1003,
        ArchGetGs = 0x1004,
    }
}
