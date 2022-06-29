// SPDX-License-Identifier: Apache-2.0

use super::{Allocator, Commit, Committer};
use crate::Result;

use core::borrow::Borrow;
use core::iter::once;
use core::marker::PhantomData;
use core::ptr::NonNull;

/// Reference to an allocated input segment.
#[derive(Debug, PartialEq, Eq)]
pub struct InRef<'a, T: ?Sized> {
    pub(super) ptr: NonNull<T>,

    /// Byte offset within block.
    pub(super) offset: usize,

    phantom: PhantomData<&'a mut T>,
}

impl<'a, T: ?Sized> InRef<'a, T> {
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
    pub(super) fn as_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<'a, T: ?Sized> InRef<'a, T> {
    #[inline]
    pub(super) fn cast<U>(self) -> InRef<'a, U> {
        InRef::new(self.ptr.cast(), self.offset)
    }

    #[inline]
    pub(super) fn cast_slice<U>(self, len: usize) -> InRef<'a, [U]> {
        InRef::new(
            NonNull::slice_from_raw_parts(self.ptr.cast(), len),
            self.offset,
        )
    }
}

impl<'a, T> InRef<'a, [T]> {
    /// Returns the number of allocated elements of type `T`.
    #[inline]
    pub fn len(&self) -> usize {
        self.ptr.len()
    }
}

impl<T: Copy> InRef<'_, T> {
    /// Copies `T` from `src.borrow()` into the allocated input segment.
    /// The source and destination may *not* overlap.
    #[inline]
    pub fn copy_from(&mut self, _: &impl Committer, src: impl Borrow<T>) {
        unsafe { self.as_ptr().copy_from_nonoverlapping(src.borrow(), 1) }
    }
}

impl<T: ?Sized + Copy> InRef<'_, [T]> {
    /// Copies `dest.map(|buf| buf.as_ref().len()).sum()` values from `src` to `self` items.
    /// The source and destination may *not* overlap.
    ///
    /// # Safety
    ///
    /// Calling this method with a `dest`, for which `dest.map(|buf| buf.as_ref().len()).sum() > self.len()` is *[undefined behavior]*.
    ///
    /// [undefined behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
    #[inline]
    pub unsafe fn copy_from_iter_unchecked(
        &mut self,
        _: &impl Committer,
        dest: impl IntoIterator<Item = impl AsRef<[T]>>,
    ) {
        dest.into_iter()
            .fold(self.as_ptr().cast::<T>(), |ptr, src| {
                let src = src.as_ref();
                let len = src.len();
                ptr.copy_from_nonoverlapping(src.as_ptr(), len);
                ptr.add(len)
            });
    }

    /// Copies `src.as_ref().len()` values from `src` to `dest`. The source and destination may *not* overlap.
    ///
    /// # Safety
    ///
    /// Calling this method with a `src`, for which `src.as_ref().len() > self.len()` is *[undefined behavior]*.
    ///
    /// [undefined behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
    #[inline]
    pub unsafe fn copy_from_unchecked(&mut self, com: &impl Committer, src: impl AsRef<[T]>) {
        self.copy_from_iter_unchecked(com, once(src))
    }
}

/// Allocated input.
pub struct Input<'a, T: ?Sized, U> {
    data_ref: InRef<'a, T>,
    val: U,
}

impl<'a, T: ?Sized, U> Input<'a, T, U> {
    /// Contructs a new [Input].
    ///
    /// # Safety
    ///
    /// Callers must ensure that the passed reference and value have the same size.
    ///
    #[inline]
    pub unsafe fn new_unchecked(data_ref: InRef<'a, T>, val: U) -> Self {
        Self { data_ref, val }
    }
}

impl<T: ?Sized, U> Input<'_, T, U> {
    /// Returns the byte offset within block.
    #[inline]
    pub fn offset(&self) -> usize {
        self.data_ref.offset()
    }
}

impl<T, U> Input<'_, [T], U> {
    /// Returns the number of allocated elements of type `T`.
    #[inline]
    pub fn len(&self) -> usize {
        self.data_ref.len()
    }
}

impl<'a, T> InRef<'a, T> {
    #[inline]
    pub fn stage<U: Borrow<T>>(self, val: U) -> Input<'a, T, U> {
        Input {
            data_ref: self,
            val,
        }
    }
}

impl<'a, T> InRef<'a, [T]> {
    #[inline]
    pub fn stage_slice<U: AsRef<[T]>>(self, val: U) -> Input<'a, [T], U> {
        Input {
            data_ref: self,
            val,
        }
    }
}

impl<'a, T, U: Borrow<T>> Input<'a, T, U> {
    /// Attempts to allocate input segment to fit `val` in the block
    /// and returns the resulting [`Input`] on success.
    #[inline]
    pub fn stage(alloc: &mut impl Allocator, val: U) -> Result<Self> {
        alloc
            .allocate_input()
            .map(move |data_ref| data_ref.stage(val))
    }
}

impl<'a, T, U: AsRef<[T]>> Input<'a, [T], U> {
    /// Attempts to allocate input segment to fit `val.len()` elements of `val` in the block
    /// and returns the resulting [`Input`] on success.
    #[inline]
    pub fn stage_slice(alloc: &mut impl Allocator, val: U) -> Result<Self> {
        alloc
            .allocate_input_slice(val.as_ref().len())
            .map(move |data_ref| data_ref.stage_slice(val))
    }
}

impl<'a, T> Input<'a, [T], &'a [T]> {
    /// Attempts to allocate input segment to fit as many elements of `val` in the block as capacity allows
    /// and returns the resulting [`Input`] on success.
    #[inline]
    pub fn stage_slice_max(alloc: &mut impl Allocator, val: &'a [T]) -> Result<(Self, &'a [T])> {
        let (head, tail) = val.split_at(val.len().min(alloc.free::<T>()));
        Self::stage_slice(alloc, head).map(|input| (input, tail))
    }
}

impl<'a, T: Copy, U: Borrow<T>> Commit for Input<'a, T, U> {
    type Item = ();

    #[inline]
    fn commit(mut self, com: &impl Committer) {
        self.data_ref.copy_from(com, self.val)
    }
}

impl<'a, T: ?Sized + Copy, U: AsRef<[T]>> Commit for Input<'a, [T], U> {
    type Item = ();

    #[inline]
    fn commit(mut self, com: &impl Committer) {
        unsafe { self.data_ref.copy_from_unchecked(com, self.val) }
    }
}
