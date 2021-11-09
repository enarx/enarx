// SPDX-License-Identifier: Apache-2.0

use libc::c_int;

/// Platform-specific functionality.
pub trait Platform {
    /// Suspend guest execution and pass control to host.
    /// This function will return when the host passes control back to the guest.
    fn sally(&mut self) -> Result<(), c_int>;

    /// Validates that a region of memory is valid for read-write access.
    /// Returns a mutable borrow if valid, otherwise [`EINVAL`](libc::EINVAL).
    fn validate_mut<'a, T>(&self, ptr: usize) -> Result<&'a mut T, c_int>;

    /// Validates that a region of memory is valid for read-only access.
    /// Returns an immutable borrow if valid, otherwise [`EINVAL`](libc::EINVAL).
    fn validate<'a, T>(&self, ptr: usize) -> Result<&'a T, c_int> {
        self.validate_mut(ptr).map(|v| v as _)
    }

    /// Validates that a region of memory is valid for read-write access for `len` elements of type `T`.
    /// Returns a mutable borrow if valid, otherwise [`EINVAL`](libc::EINVAL).
    fn validate_slice_mut<'a, T>(&self, ptr: usize, len: usize) -> Result<&'a mut [T], c_int>;

    /// Validates that a region of memory is valid for read-only access for `len` elements of type `T`.
    /// Returns a mutable borrow if valid, otherwise [`EINVAL`](libc::EINVAL).
    fn validate_slice<'a, T>(&self, ptr: usize, len: usize) -> Result<&'a [T], c_int> {
        self.validate_slice_mut(ptr, len).map(|v| v as _)
    }
}
