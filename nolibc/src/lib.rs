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

/// Buffer used by readv() and writev() syscalls
#[repr(C)]
pub struct Iovec<'a> {
    /// Buffer start address
    pub base: *mut u8,

    /// Number of bytes to transfer
    pub size: usize,

    phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> AsRef<[u8]> for Iovec<'a> {
    fn as_ref(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.base, self.size) }
    }
}

impl<'a> AsMut<[u8]> for Iovec<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.base, self.size) }
    }
}

const UTSNAME_LENGTH: usize = 65;

#[repr(C)]
pub struct UtsName {
    pub sysname: [u8; UTSNAME_LENGTH],
    pub nodename: [u8; UTSNAME_LENGTH],
    pub release: [u8; UTSNAME_LENGTH],
    pub version: [u8; UTSNAME_LENGTH],
    pub machine: [u8; UTSNAME_LENGTH],
}
