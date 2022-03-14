// SPDX-License-Identifier: Apache-2.0

//! Allocation-specific functionality.

#[cfg(test)]
mod tests;

mod inout;
mod input;
mod output;
mod phase_alloc;

pub use inout::*;
pub use input::*;
pub use output::*;

pub(super) use phase_alloc::*;

use crate::libc::EOVERFLOW;
use crate::Result;

use core::alloc::Layout;

/// Returns a [`Layout`] corresponding to an array of `len` elements of type `T`.
#[inline]
fn array_layout<T>(len: usize) -> Result<Layout> {
    Layout::array::<T>(len).map_err(|_| EOVERFLOW)
}

/// Allocator in stage phase.
pub trait Allocator {
    type Committer: Committer;

    /// Returns amount of elements of type `T` that can still be allocated.
    fn free<T>(&self) -> usize;

    /// Creates a new section and returns the size of it in bytes.
    fn section<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<(T, usize)>;

    /// Attempts to allocate an arbitrary input [`Layout`]
    /// and returns corresponding [`InRef`] on success.
    fn allocate_input_layout<'a>(&mut self, layout: Layout) -> Result<InRef<'a, [u8]>>;

    /// Attempts to allocate an arbitrary output [`Layout`]
    /// and returns corresponding [`OutRef`] on success.
    fn allocate_output_layout<'a>(&mut self, layout: Layout) -> Result<OutRef<'a, [u8]>>;

    /// Attempts to allocate an arbitrary inout [`Layout`]
    /// and returns corresponding [`InOutRef`] on success.
    fn allocate_inout_layout<'a>(&mut self, layout: Layout) -> Result<InOutRef<'a, [u8]>>;

    /// Attempts to reserve an arbitrary input [`Layout`]
    /// and returns corresponding [`InRef`] on success.
    fn reserve_input_layout<'a, T, F>(
        &mut self,
        layout: Layout,
        f: F,
    ) -> Result<(T, InRef<'a, [u8]>)>
    where
        F: FnOnce(&mut Self) -> Result<T>;

    /// Attempts to reserve an arbitrary output [`Layout`]
    /// and returns corresponding [`OutRef`] on success.
    fn reserve_output_layout<'a, T, F>(
        &mut self,
        layout: Layout,
        f: F,
    ) -> Result<(T, OutRef<'a, [u8]>)>
    where
        F: FnOnce(&mut Self) -> Result<T>;

    /// Attempts to reserve an arbitrary inout [`Layout`]
    /// and returns corresponding [`InOutRef`] on success.
    fn reserve_inout_layout<'a, T, F>(
        &mut self,
        layout: Layout,
        f: F,
    ) -> Result<(T, InOutRef<'a, [u8]>)>
    where
        F: FnOnce(&mut Self) -> Result<T>;

    /// Attempts to allocate an input of type `T`
    /// and returns corresponding [`InRef`] on success.
    #[inline]
    fn allocate_input<'a, T>(&mut self) -> Result<InRef<'a, T>> {
        self.allocate_input_layout(Layout::new::<T>())
            .map(InRef::cast)
    }

    /// Attempts to allocate an output of type `T`
    /// and returns corresponding [`OutRef`] on success.
    #[inline]
    fn allocate_output<'a, T>(&mut self) -> Result<OutRef<'a, T>> {
        self.allocate_output_layout(Layout::new::<T>())
            .map(OutRef::cast)
    }

    /// Attempts to allocate an inout of type `T`
    /// and returns corresponding [`InOutRef`] on success.
    #[inline]
    fn allocate_inout<'a, T>(&mut self) -> Result<InOutRef<'a, T>> {
        self.allocate_inout_layout(Layout::new::<T>())
            .map(InOutRef::cast)
    }

    /// Attempts to reserve an input of type `T`
    /// and returns corresponding [`InRef`] on success.
    #[inline]
    fn reserve_input<'a, T, U>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<U>,
    ) -> Result<(U, InRef<'a, T>)> {
        self.reserve_input_layout(Layout::new::<T>(), f)
            .map(|(data, reserved)| (data, reserved.cast()))
    }

    /// Attempts to reserve an output of type `T`
    /// and returns corresponding [`OutRef`] on success.
    #[inline]
    fn reserve_output<'a, T, U>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<U>,
    ) -> Result<(U, OutRef<'a, T>)> {
        self.reserve_output_layout(Layout::new::<T>(), f)
            .map(|(data, reserved)| (data, reserved.cast()))
    }

    /// Attempts to reserve an inout of type `T`
    /// and returns corresponding [`InOutRef`] on success.
    #[inline]
    fn reserve_inout<'a, T, U>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<U>,
    ) -> Result<(U, InOutRef<'a, T>)> {
        self.reserve_inout_layout(Layout::new::<T>(), f)
            .map(|(data, reserved)| (data, reserved.cast()))
    }

    /// Attempts to allocate a slice input of `len` elements of type `T`
    /// and returns corresponding [`InRef`] on success.
    #[inline]
    fn allocate_input_slice<'a, T>(&mut self, len: usize) -> Result<InRef<'a, [T]>> {
        self.allocate_input_layout(array_layout::<T>(len)?)
            .map(|r| r.cast_slice(len))
    }

    /// Attempts to allocate a slice input of at most `len` elements of type `T` depending on capacity
    /// and returns corresponding [`InRef`] on success.
    #[inline]
    fn allocate_input_slice_max<'a, T>(&mut self, len: usize) -> Result<InRef<'a, [T]>> {
        self.allocate_input_slice(len.min(self.free::<T>()))
    }

    /// Attempts to allocate a slice output of `len` elements of type `T`
    /// and returns corresponding [`OutRef`] on success.
    #[inline]
    fn allocate_output_slice<'a, T>(&mut self, len: usize) -> Result<OutRef<'a, [T]>> {
        self.allocate_output_layout(array_layout::<T>(len)?)
            .map(|r| r.cast_slice(len))
    }

    /// Attempts to allocate a slice output of at most `len` elements of type `T` depending on capacity
    /// and returns corresponding [`OutRef`] on success.
    #[inline]
    fn allocate_output_slice_max<'a, T>(&mut self, len: usize) -> Result<OutRef<'a, [T]>> {
        self.allocate_output_slice(len.min(self.free::<T>()))
    }

    /// Attempts to allocate a slice inout of `len` elements of type `T`
    /// and returns corresponding [`InOutRef`] on success.
    #[inline]
    fn allocate_inout_slice<'a, T>(&mut self, len: usize) -> Result<InOutRef<'a, [T]>> {
        self.allocate_inout_layout(array_layout::<T>(len)?)
            .map(|r| r.cast_slice(len))
    }

    /// Attempts to allocate a slice inout of at most `len` elements of type `T` depending on capacity
    /// and returns corresponding [`InOutRef`] on success.
    #[inline]
    fn allocate_inout_slice_max<'a, T>(&mut self, len: usize) -> Result<InOutRef<'a, [T]>> {
        self.allocate_inout_slice(len.min(self.free::<T>()))
    }

    /// Records the end of stage phase and moves allocator into commit phase.
    fn commit(self) -> Self::Committer;
}

/// Something that can be staged in stage phase.
pub trait Stage<'a> {
    type Item;

    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item>;
}

impl<'a, T: Stage<'a>> Stage<'a> for Option<T> {
    type Item = Option<T::Item>;

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        self.map(|v| v.stage(alloc)).transpose()
    }
}

impl Stage<'_> for () {
    type Item = ();

    #[inline]
    fn stage(self, _: &mut impl Allocator) -> Result<()> {
        Ok(())
    }
}

impl<'a, A: Stage<'a>> Stage<'a> for (A,) {
    type Item = (A::Item,);

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        self.0.stage(alloc).map(|a| (a,))
    }
}

impl<'a, A: Stage<'a>, B: Stage<'a>> Stage<'a> for (A, B) {
    type Item = (A::Item, B::Item);

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        let a = self.0.stage(alloc)?;
        let b = self.1.stage(alloc)?;
        Ok((a, b))
    }
}

impl<'a, A: Stage<'a>, B: Stage<'a>, C: Stage<'a>> Stage<'a> for (A, B, C) {
    type Item = (A::Item, B::Item, C::Item);

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        ((self.0, self.1), self.2)
            .stage(alloc)
            .map(|((a, b), c)| (a, b, c))
    }
}

impl<'a, A: Stage<'a>, B: Stage<'a>, C: Stage<'a>, D: Stage<'a>> Stage<'a> for (A, B, C, D) {
    type Item = (A::Item, B::Item, C::Item, D::Item);

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        ((self.0, self.1), self.2, self.3)
            .stage(alloc)
            .map(|((a, b), c, d)| (a, b, c, d))
    }
}

/// Allocator in commit phase.
pub trait Committer: phase::Alloc {
    type Collector: Collector;

    /// Records the end of commit phase and moves allocator into collect phase.
    fn collect(self) -> Self::Collector;
}

/// Something that can be committed in commit phase.
pub trait Commit {
    type Item;

    fn commit(self, com: &impl Committer) -> Self::Item;
}

impl<T: Commit> Commit for Option<T> {
    type Item = Option<T::Item>;

    #[inline]
    fn commit(self, com: &impl Committer) -> Self::Item {
        self.map(|v| v.commit(com))
    }
}

impl Commit for () {
    type Item = ();

    #[inline]
    fn commit(self, _: &impl Committer) {}
}

impl<A: Commit> Commit for (A,) {
    type Item = (A::Item,);

    #[inline]
    fn commit(self, com: &impl Committer) -> Self::Item {
        (self.0.commit(com),)
    }
}

impl<A: Commit, B: Commit> Commit for (A, B) {
    type Item = (A::Item, B::Item);

    #[inline]
    fn commit(self, com: &impl Committer) -> Self::Item {
        (self.0.commit(com), self.1.commit(com))
    }
}

impl<A: Commit, B: Commit, C: Commit> Commit for (A, B, C) {
    type Item = (A::Item, B::Item, C::Item);

    #[inline]
    fn commit(self, com: &impl Committer) -> Self::Item {
        (self.0.commit(com), self.1.commit(com), self.2.commit(com))
    }
}

impl<A: Commit, B: Commit, C: Commit, D: Commit> Commit for (A, B, C, D) {
    type Item = (A::Item, B::Item, C::Item, D::Item);

    #[inline]
    fn commit(self, com: &impl Committer) -> Self::Item {
        (
            self.0.commit(com),
            self.1.commit(com),
            self.2.commit(com),
            self.3.commit(com),
        )
    }
}

/// Something, for which [`Commit::commit`] is an identity function.
pub trait CommitPassthrough {}

impl<T: CommitPassthrough> Commit for T {
    type Item = Self;

    fn commit(self, _: &impl Committer) -> Self::Item {
        self
    }
}

/// Allocator in collection phase.
pub trait Collector: phase::Alloc {}

/// Something that can be collected in collection phase.
pub trait Collect {
    type Item;

    fn collect(self, col: &impl Collector) -> Self::Item;
}

impl<T: Collect> Collect for Option<T> {
    type Item = Option<T::Item>;

    #[inline]
    fn collect(self, col: &impl Collector) -> Self::Item {
        self.map(|v| v.collect(col))
    }
}

impl<A: Collect> Collect for (A,) {
    type Item = (A::Item,);

    #[inline]
    fn collect(self, col: &impl Collector) -> Self::Item {
        (self.0.collect(col),)
    }
}

impl<A: Collect, B: Collect> Collect for (A, B) {
    type Item = (A::Item, B::Item);

    #[inline]
    fn collect(self, col: &impl Collector) -> Self::Item {
        (self.0.collect(col), self.1.collect(col))
    }
}

impl<A: Collect, B: Collect, C: Collect> Collect for (A, B, C) {
    type Item = (A::Item, B::Item, C::Item);

    #[inline]
    fn collect(self, col: &impl Collector) -> Self::Item {
        (
            self.0.collect(col),
            self.1.collect(col),
            self.2.collect(col),
        )
    }
}

impl<A: Collect, B: Collect, C: Collect, D: Collect> Collect for (A, B, C, D) {
    type Item = (A::Item, B::Item, C::Item, D::Item);

    #[inline]
    fn collect(self, col: &impl Collector) -> Self::Item {
        (
            self.0.collect(col),
            self.1.collect(col),
            self.2.collect(col),
            self.3.collect(col),
        )
    }
}
