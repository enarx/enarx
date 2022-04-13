// SPDX-License-Identifier: Apache-2.0

use super::syscall::types::SockaddrOutput;
use crate::libc::{iovec, EINVAL};

use core::ffi::c_int;
use core::slice;

/// Platform-specific functionality.
pub trait Platform {
    /// Validates that the memory pointed to by `ptr` of the type `T` is:
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed mutably.
    ///
    /// Returns a mutable borrow if valid, otherwise [`EINVAL`](libc::EINVAL).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    fn validate_mut<T>(&self, ptr: usize) -> Result<&mut T, c_int>;

    /// Validates that the memory pointed to by `ptr` of the type `T` is:
    /// * in valid address space and readable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed.
    ///
    /// Returns an immutable borrow if valid, otherwise [`EINVAL`](libc::EINVAL).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    fn validate<T>(&self, ptr: usize) -> Result<&T, c_int>;

    /// Validates that a region for `count` elements of type `T` is:
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed mutably.
    ///
    /// Returns a mutable borrow if valid, otherwise [`EINVAL`](libc::EINVAL).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    fn validate_slice_mut<T: Sized>(&self, ptr: usize, count: usize) -> Result<&mut [T], c_int>;

    /// Validates that a region of memory is valid for read-only access for `count` elements of type `T`.
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed.
    ///
    /// Returns an immutable borrow if valid, otherwise [`EINVAL`](libc::EINVAL).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    fn validate_slice<T: Sized>(&self, ptr: usize, count: usize) -> Result<&[T], c_int>;

    /// Validates that pointer `iov` points to represents a slice of `iovcnt` pointers to [`libc::iovec`] structures
    /// valid for read-write access.
    ///
    /// Also checks, that memory is:
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * not borrowed already
    /// * and pointers are non-null and aligned
    /// and registers the memory as borrowed mutably.
    ///
    /// Returns a mutable borrow of the [`libc::iovec`] structs as a 2-dimensional slice
    /// of mutable byte buffer borrows if valid, otherwise [`EINVAL`](libc::EINVAL).
    #[inline]
    fn validate_iovec_slice_mut(
        &self,
        iov: usize,
        iovcnt: usize,
    ) -> Result<&mut [&mut [u8]], c_int> {
        let iovec_slice = self.validate_slice::<iovec>(iov, iovcnt)?;
        for iovec in iovec_slice {
            self.validate_slice_mut::<u8>(iovec.iov_base as _, iovec.iov_len)?;
        }

        // Safety: checked all slices before
        Ok(unsafe { slice::from_raw_parts_mut(iov as _, iovcnt) })
    }

    /// Validates that pointer `iov` points to represents a slice of `iovcnt` pointers to [`libc::iovec`] structures
    /// valid for read-only access.
    ///
    /// Also checks, that the memory is:
    /// * in valid address space and readable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * not borrowed already
    /// * and pointers are non-null and aligned
    /// and registers the memory as borrowed.
    ///
    /// Returns an immutable borrow of the [`libc::iovec`] structs as a 2-dimensional slice
    /// of immutable byte buffer borrows if valid, otherwise [`EINVAL`](libc::EINVAL).
    #[inline]
    fn validate_iovec_slice(&self, iov: usize, iovcnt: usize) -> Result<&[&[u8]], c_int> {
        let iovec_slice = self.validate_slice::<iovec>(iov, iovcnt)?;
        for iovec in iovec_slice {
            self.validate_slice::<u8>(iovec.iov_base as _, iovec.iov_len)?;
        }

        // Safety: checked all slices before
        Ok(unsafe { slice::from_raw_parts(iov as _, iovcnt) })
    }

    /// Validates that a region of memory represents a C string and is valid for read-only access.
    ///
    /// Also checks, that the memory is:
    /// * in valid address space and readable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed.
    ///
    /// Returns an immutable borrow of bytes of the string with the nul terminator byte if valid,
    /// otherwise [`EINVAL`](libc::EINVAL).
    #[inline]
    fn validate_str(&self, ptr: usize) -> Result<&[u8], c_int> {
        let mut p = ptr;

        loop {
            let byte = self.validate::<u8>(p)?;
            p += 1;
            if *byte == 0 {
                break;
            }
        }

        let len = p.checked_sub(ptr).ok_or(EINVAL)?;

        // Safety: checked all bytes before
        Ok(unsafe { slice::from_raw_parts(ptr as *const u8, len) })
    }

    /// Validates that pointer `addrlen` points to `socklen_t` and `addr` points to
    /// a byte array of size `*addrlen` and is valid for read-write access.
    ///
    /// Also checks that the memory is:
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * not borrowed already
    /// * and pointers are non-null and aligned
    /// and registers the memory as borrowed.
    ///
    /// Returns a `SockaddrOutput`, otherwise [`EINVAL`](libc::EINVAL).
    #[inline]
    fn validate_sockaddr_output(
        &self,
        addr: usize,
        addrlen: usize,
    ) -> Result<SockaddrOutput, c_int> {
        let addrlen = self.validate_mut(addrlen)?;
        let addr = self.validate_slice_mut(addr, *addrlen as _)?;
        Ok(SockaddrOutput::new(addr, addrlen))
    }
}
