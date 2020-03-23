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

// TODO: These functions are naive implementations that are not performant.

/// # Safety
///
/// All libc functions are unsafe.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        *dst.add(i) = *src.add(i);
    }

    dst
}

/// # Safety
///
/// All libc functions are unsafe.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, src: u8, n: usize) -> *mut u8 {
    for i in 0..n {
        *dst.add(i) = src;
    }

    dst
}

/// # Safety
///
/// All libc functions are unsafe.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn bcmp(l: *const u8, r: *const u8, n: usize) -> usize {
    let mut neq = 0;

    for i in 0..n {
        neq |= (*l.add(i) != *r.add(i)) as usize;
    }

    neq
}

#[cfg(test)]
mod tests {
    #[test]
    fn memcpy() {
        let src: [u8; 3] = [1, 2, 3];
        let mut dst: [u8; 5] = [0; 5];

        let ret = unsafe { super::memcpy(dst.as_mut_ptr(), src.as_ptr(), 3) };
        assert_eq!(ret, dst.as_mut_ptr());
        assert_eq!(dst, [1, 2, 3, 0, 0]);
    }

    #[test]
    fn memset() {
        let mut dst: [u8; 5] = [0; 5];

        let ret = unsafe { super::memset(dst.as_mut_ptr(), 1, 3) };
        assert_eq!(ret, dst.as_mut_ptr());
        assert_eq!(dst, [1, 1, 1, 0, 0]);
    }

    #[test]
    fn bcmp() {
        let l: [u8; 5] = [1, 2, 3, 0, 0];
        let r: [u8; 5] = [1, 2, 3, 1, 1];

        let ret = unsafe { super::bcmp(l.as_ptr(), r.as_ptr(), 3) };
        assert_eq!(ret, 0);

        let ret = unsafe { super::bcmp(l.as_ptr(), r.as_ptr(), 5) };
        assert_ne!(ret, 0);
    }
}
