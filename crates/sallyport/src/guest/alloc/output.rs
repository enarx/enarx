// SPDX-License-Identifier: Apache-2.0

use super::{Allocator, Collect, Collector, Commit, Committer};
use crate::Result;

use core::borrow::BorrowMut;
use core::iter::once;
use core::marker::PhantomData;
use core::ops::Range;
use core::ptr::NonNull;

/// Reference to an allocated output segment.
#[derive(Debug, PartialEq, Eq)]
pub struct OutRef<'a, T: ?Sized> {
    pub(super) ptr: NonNull<T>,

    /// Byte offset within block.
    pub(super) offset: usize,

    phantom: PhantomData<&'a T>,
}

impl<'a, T: ?Sized> OutRef<'a, T> {
    #[inline]
    pub(super) fn new(ptr: NonNull<T>, offset: usize) -> Self {
        Self {
            ptr,
            offset,
            phantom: PhantomData,
        }
    }

    /// Returns the byte offset within block.
    #[inline]
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    pub(super) fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }
}

impl<'a, T: ?Sized> OutRef<'a, T> {
    #[inline]
    pub(super) fn cast<U>(self) -> OutRef<'a, U> {
        OutRef::new(self.ptr.cast(), self.offset)
    }

    #[inline]
    pub(super) fn cast_slice<U>(self, len: usize) -> OutRef<'a, [U]> {
        OutRef::new(
            NonNull::slice_from_raw_parts(self.ptr.cast(), len),
            self.offset,
        )
    }
}

impl<'a, T> OutRef<'a, [T]> {
    /// Returns the number of allocated elements of type `T`.
    #[inline]
    pub fn len(&self) -> usize {
        self.ptr.len()
    }
}

impl<T: Copy> OutRef<'_, T> {
    /// Copies the value from `self` to `dest`. The source and destination may *not* overlap.
    #[inline]
    pub fn copy_to(&self, _: &impl Collector, mut dest: impl BorrowMut<T>) {
        unsafe { self.as_ptr().copy_to_nonoverlapping(dest.borrow_mut(), 1) }
    }
}

impl<'a, T: ?Sized + Copy> OutRef<'a, [T]> {
    /// Copies `dest.map(|buf| buf.as_mut().len()).sum()` values from `self` to `dest`.  The source and destination may *not* overlap.
    ///
    /// # Safety
    ///
    /// Calling this method with a `dest`, for which `dest.map(|buf| buf.as_mut().len()).sum() > self.len()` is *[undefined behavior]*.
    ///
    /// [undefined behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
    #[inline]
    pub unsafe fn copy_to_iter_unchecked(
        &self,
        _: &impl Collector,
        dest: impl IntoIterator<Item = impl AsMut<[T]>>,
    ) {
        dest.into_iter()
            .fold(self.as_ptr().cast::<T>(), |ptr, mut dest| {
                let dest = dest.as_mut();
                let len = dest.len();
                ptr.copy_to_nonoverlapping(dest.as_mut_ptr(), len);
                ptr.add(len)
            });
    }

    /// Copies `dest.as_mut().len()` values from `self` to `dest.as_mut()`. The source and destination may *not* overlap.
    ///
    /// # Safety
    ///
    /// Calling this method with a `dest`, for which `dest.as_mut().len() > self.len()` is *[undefined behavior]*.
    ///
    /// [undefined behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
    #[inline]
    pub unsafe fn copy_to_unchecked(&self, col: &impl Collector, dest: impl AsMut<[T]>) {
        self.copy_to_iter_unchecked(col, once(dest))
    }
}

/// Allocated output.
pub struct Output<'a, T: ?Sized, U> {
    data_ref: OutRef<'a, T>,
    val: U,
}

impl<'a, T: ?Sized, U> Output<'a, T, U> {
    /// Contructs a new [Output].
    ///
    /// # Safety
    ///
    /// Callers must ensure that the passed reference and value have the same size.
    ///
    #[inline]
    pub unsafe fn new_unchecked(data_ref: OutRef<'a, T>, val: U) -> Self {
        Self { data_ref, val }
    }
}

impl<T: ?Sized, U> Output<'_, T, U> {
    /// Returns the byte offset within block.
    #[inline]
    pub fn offset(&self) -> usize {
        self.data_ref.offset()
    }
}

impl<T, U> Output<'_, [T], U> {
    /// Returns the number of allocated elements of type `T`.
    #[inline]
    pub fn len(&self) -> usize {
        self.data_ref.len()
    }
}

impl<'a, T, U: BorrowMut<T>> Output<'a, T, U> {
    /// Attempts to allocate input segment to fit `val` in the block
    /// and returns the resulting [`Output`] on success.
    #[inline]
    pub fn stage(alloc: &mut impl Allocator, val: U) -> Result<Self> {
        alloc
            .allocate_output()
            .map(move |data_ref| Output { data_ref, val })
    }
}

impl<'a, T, U: AsMut<[T]>> Output<'a, [T], U> {
    /// Attempts to allocate input segment to fit `val.len()` elements of `val` in the block
    /// and returns the resulting [`Output`] on success.
    #[inline]
    pub fn stage_slice(alloc: &mut impl Allocator, mut val: U) -> Result<Self> {
        alloc
            .allocate_output_slice(val.as_mut().len())
            .map(move |data_ref| Output { data_ref, val })
    }
}

impl<'a, T> Output<'a, [T], &'a mut [T]> {
    /// Attempts to allocate input segment to fit as many elements of `val` in the block as capacity allows
    /// and returns the resulting [`Output`] on success.
    #[inline]
    pub fn stage_slice_max(
        alloc: &mut impl Allocator,
        val: &'a mut [T],
    ) -> Result<(Self, &'a mut [T])> {
        let (head, tail) = val.split_at_mut(val.len().min(alloc.free::<T>()));
        Self::stage_slice(alloc, head).map(|output| (output, tail))
    }
}

impl<T: ?Sized, U> Commit for Output<'_, T, U> {
    type Item = Self;

    #[inline]
    fn commit(self, _: &impl Committer) -> Self::Item {
        self
    }
}

impl<'a, T: Copy, U: BorrowMut<T>> Collect for Output<'a, T, U> {
    type Item = U;

    #[inline]
    fn collect(mut self, col: &impl Collector) -> Self::Item {
        self.data_ref.copy_to(col, self.val.borrow_mut());
        self.val
    }
}

impl<'a, T: ?Sized + Copy, U: AsMut<[T]>> Collect for Output<'a, [T], U> {
    type Item = U;

    #[inline]
    fn collect(mut self, col: &impl Collector) -> Self::Item {
        unsafe { self.data_ref.copy_to_unchecked(col, self.val.as_mut()) };
        self.val
    }
}

impl<'a, T: ?Sized + Copy, U: AsMut<[T]>> Output<'a, [T], U> {
    /// Copies data from the block to `range` within the contained value and returns it.
    ///
    /// # Safety
    ///
    /// Calling this method with a `range`, for which `range.len() > self.len()` is *[undefined behavior]*.
    ///
    /// [undefined behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
    #[inline]
    pub unsafe fn collect_range(mut self, col: &impl Collector, range: Range<usize>) -> U {
        self.data_ref
            .copy_to_unchecked(col, &mut self.val.as_mut()[range]);
        self.val
    }
}
