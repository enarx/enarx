// SPDX-License-Identifier: Apache-2.0

use super::Bounds;

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::cmp::min;

/// Provides a page-aligned data buffer.
///
/// The purpose of this type is to provide page-aligned data for inputs to
/// SGX functions. The code in the static binaries is not always page aligned.
/// But SGX functions require page-aligned data inputs.
pub struct Paged(Layout, *mut u8);

impl Drop for Paged {
    fn drop(&mut self) {
        unsafe { dealloc(self.1, self.0) }
    }
}

impl AsRef<[u8]> for Paged {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.1, self.0.size()) }
    }
}

impl AsMut<[u8]> for Paged {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.1, self.0.size()) }
    }
}

impl Paged {
    pub const PAGE: usize = 0x1000;

    /// Creates `pages` of page-aligned, zeroed buffer.
    pub fn zeroed(pages: usize) -> Self {
        let lay = Layout::from_size_align(Self::PAGE * pages, Self::PAGE).unwrap();

        Paged(lay, unsafe { alloc_zeroed(lay) })
    }

    /// Expands source data and bounds to be page aligned.
    pub fn expand<T: AsRef<[u8]> + ?Sized>(src: &T, dst: Bounds) -> (Self, Bounds) {
        let bytes = min(src.as_ref().len(), dst.count.inner());
        let start = dst.start.align(false, Self::PAGE);
        let prefx = dst.start - start;
        let count = (dst.count + prefx).align(true, Self::PAGE);

        let mut buf = Self::zeroed(count.inner() / Self::PAGE);

        // Copy bytes from the old src to the paged src.
        buf.as_mut()[prefx.inner()..][..bytes].copy_from_slice(&src.as_ref()[..bytes]);

        (buf, Bounds { start, count })
    }
}
