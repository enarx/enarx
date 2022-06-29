// SPDX-License-Identifier: Apache-2.0

use super::{Allocator, Commit, Committer, InRef, OutRef, Output};
use crate::Result;

use core::borrow::BorrowMut;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

/// Reference to an allocated input-output segment.
#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct InOutRef<'a, T: ?Sized>(InRef<'a, T>);

impl<'a, T: ?Sized> InOutRef<'a, T> {
    #[inline]
    pub(super) fn new(ptr: NonNull<T>, offset: usize) -> Self {
        Self(InRef::new(ptr, offset))
    }

    #[inline]
    pub(super) fn cast<U>(self) -> InOutRef<'a, U> {
        InOutRef(self.0.cast())
    }

    #[inline]
    pub(super) fn cast_slice<U>(self, len: usize) -> InOutRef<'a, [U]> {
        InOutRef(self.0.cast_slice(len))
    }
}

impl<'a, T: ?Sized> From<InOutRef<'a, T>> for OutRef<'a, T> {
    #[inline]
    fn from(r: InOutRef<'a, T>) -> Self {
        Self::new(r.ptr, r.offset)
    }
}

impl<'a, T: ?Sized> Deref for InOutRef<'a, T> {
    type Target = InRef<'a, T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, T: ?Sized> DerefMut for InOutRef<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, T: ?Sized> Commit for InOutRef<'a, T> {
    type Item = OutRef<'a, T>;

    #[inline]
    fn commit(self, _: &impl Committer) -> Self::Item {
        self.into()
    }
}

/// Allocated inout.
pub struct InOut<'a, T: ?Sized, U> {
    data_ref: InOutRef<'a, T>,
    val: U,
}

impl<'a, T: ?Sized, U> InOut<'a, T, U> {
    /// Contructs a new [InOut].
    ///
    /// # Safety
    ///
    /// Callers must ensure that the passed reference and value have the same size.
    ///
    #[inline]
    pub unsafe fn new_unchecked(data_ref: InOutRef<'a, T>, val: U) -> Self {
        Self { data_ref, val }
    }
}

impl<T: ?Sized, U> InOut<'_, T, U> {
    /// Returns the byte offset within block.
    #[inline]
    pub fn offset(&self) -> usize {
        self.data_ref.offset()
    }
}

impl<T, U> InOut<'_, [T], U> {
    /// Returns the number of allocated elements of type `T`.
    #[inline]
    pub fn len(&self) -> usize {
        self.data_ref.len()
    }
}

impl<'a, T: ?Sized, U> From<InOut<'a, T, U>> for Output<'a, T, U> {
    #[inline]
    fn from(r: InOut<'a, T, U>) -> Self {
        unsafe { Self::new_unchecked(r.data_ref.into(), r.val) }
    }
}

impl<'a, T> InOutRef<'a, T> {
    #[inline]
    pub fn stage<U: BorrowMut<T>>(self, val: U) -> InOut<'a, T, U> {
        InOut {
            data_ref: self,
            val,
        }
    }
}

impl<'a, T> InOutRef<'a, [T]> {
    #[inline]
    pub fn stage_slice<U: AsMut<[T]>>(self, val: U) -> InOut<'a, [T], U> {
        InOut {
            data_ref: self,
            val,
        }
    }
}

impl<'a, T, U: BorrowMut<T>> InOut<'a, T, U> {
    /// Attempts to allocate inout segment to fit `val` in the block
    /// and returns the resulting [`InOut`] on success.
    #[inline]
    pub fn stage(alloc: &mut impl Allocator, val: U) -> Result<Self> {
        alloc
            .allocate_inout()
            .map(move |data_ref| data_ref.stage(val))
    }
}

impl<'a, T, U: AsMut<[T]>> InOut<'a, [T], U> {
    /// Attempts to allocate inout segment to fit `val.len()` elements of `val` in the block
    /// and returns the resulting [`InOut`] on success.
    #[inline]
    pub fn stage_slice(alloc: &mut impl Allocator, mut val: U) -> Result<Self> {
        alloc
            .allocate_inout_slice(val.as_mut().len())
            .map(move |data_ref| data_ref.stage_slice(val))
    }
}

impl<'a, T> InOut<'a, [T], &'a mut [T]> {
    /// Attempts to allocate inout segment to fit as many elements of `val` in the block as capacity allows
    /// and returns the resulting [`InOut`] on success.
    #[inline]
    pub fn stage_slice_max(
        alloc: &mut impl Allocator,
        val: &'a mut [T],
    ) -> Result<(Self, &'a mut [T])> {
        let (head, tail) = val.split_at_mut(val.len().min(alloc.free::<T>()));
        Self::stage_slice(alloc, head).map(|input| (input, tail))
    }
}

impl<'a, T: Copy, U: BorrowMut<T>> Commit for InOut<'a, T, U> {
    type Item = Output<'a, T, U>;

    #[inline]
    fn commit(mut self, com: &impl Committer) -> Self::Item {
        self.data_ref.copy_from(com, self.val.borrow_mut());
        self.into()
    }
}

impl<'a, T: ?Sized + Copy, U: AsMut<[T]>> Commit for InOut<'a, [T], U> {
    type Item = Output<'a, [T], U>;

    #[inline]
    fn commit(mut self, com: &impl Committer) -> Self::Item {
        unsafe { self.data_ref.copy_from_unchecked(com, self.val.as_mut()) };
        self.into()
    }
}
