// SPDX-License-Identifier: Apache-2.0

use super::{Commit, Committer, InRef, OutRef};

use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

/// Reference to an allocated input-output segment.
#[derive(Debug, PartialEq)]
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
        Self::Item::new(self.0.ptr, self.0.offset)
    }
}
