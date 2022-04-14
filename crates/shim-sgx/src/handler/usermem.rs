// SPDX-License-Identifier: Apache-2.0

use core::slice;
use sallyport::guest::Platform;
use sallyport::libc::EINVAL;
use sallyport::util::ptr::is_aligned_non_null;

/// Memory validation scope
pub struct UserMemScope;

impl Platform for UserMemScope {
    /// Validates that the memory pointed to by `ptr` of the type `T` is:
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed mutably.
    ///
    /// Returns a mutable borrow if valid, otherwise [`EINVAL`](https://man7.org/linux/man-pages/man3/errno.3.html).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    #[inline]
    fn validate_mut<T>(&self, ptr: usize) -> sallyport::Result<&mut T> {
        is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;

        // Safety: The pointer is now non-null aligned.
        // FIXME: ensure the lifetime and that it is not borrowed multiple times.
        // FIXME: ensure valid address space and writable https://github.com/enarx/enarx/issues/964
        unsafe { (ptr as *mut T).as_mut().ok_or(EINVAL) }
    }

    /// Validates that the memory pointed to by `ptr` of the type `T` is:
    /// * in valid address space and readable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed.
    ///
    /// Returns an immutable borrow if valid, otherwise [`EINVAL`](https://man7.org/linux/man-pages/man3/errno.3.html).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    #[inline]
    fn validate<T>(&self, ptr: usize) -> sallyport::Result<&T> {
        is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;

        // Safety: The pointer is now non-null aligned.
        // FIXME: ensure the lifetime and that it is not borrowed writeable.
        // FIXME: ensure valid address space and readable https://github.com/enarx/enarx/issues/964
        unsafe { (ptr as *const T).as_ref().ok_or(EINVAL) }
    }

    /// Validates that a region for `len` elements of type `T` is:
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed mutably.
    ///
    /// Returns a mutable borrow if valid, otherwise [`EINVAL`](https://man7.org/linux/man-pages/man3/errno.3.html).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    #[inline]
    fn validate_slice_mut<T: Sized>(
        &self,
        ptr: usize,
        count: usize,
    ) -> sallyport::Result<&mut [T]> {
        is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;

        // Safety: The pointer is now non-null aligned.
        // FIXME: ensure the lifetime and that it is not borrowed already.
        // FIXME: ensure valid address space and writable https://github.com/enarx/enarx/issues/964
        unsafe { Ok(slice::from_raw_parts_mut(ptr as *mut T, count)) }
    }

    /// Validates that a region of memory is valid for read-only access for `len` elements of type `T`.
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed.
    ///
    /// Returns an immutable borrow if valid, otherwise [`EINVAL`](https://man7.org/linux/man-pages/man3/errno.3.html).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    #[inline]
    fn validate_slice<T: Sized>(&self, ptr: usize, count: usize) -> sallyport::Result<&[T]> {
        is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;

        // Safety: The pointer is now non-null aligned.
        // FIXME: ensure the lifetime and that it is not borrowed writeable.
        // FIXME: ensure valid address space and readable https://github.com/enarx/enarx/issues/964
        unsafe { Ok(slice::from_raw_parts(ptr as *const T, count)) }
    }
}
