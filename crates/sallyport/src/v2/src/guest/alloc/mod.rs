// SPDX-License-Identifier: Apache-2.0

//! Allocation-specific functionality.

#[cfg(test)]
mod tests;

mod inout;
mod input;
mod output;
mod phase_alloc;
mod syscall;

pub use inout::*;
pub use input::*;
pub use output::*;

pub(super) use phase_alloc::*;
pub use syscall::*;

use crate::Result;

use core::alloc::Layout;
use libc::ENOMEM;

/// Returns a [`Layout`] corresponding to an array of `len` elements of type `T`.
#[inline]
fn array_layout<T>(len: usize) -> Result<Layout> {
    Layout::array::<T>(len).map_err(|_| libc::EOVERFLOW)
}

/// Allocator in stage phase.
pub trait Allocator {
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
        let len = len.min(self.free::<T>());
        if len == 0 {
            return Err(ENOMEM);
        }
        self.allocate_input_slice(len)
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
        let len = len.min(self.free::<T>());
        if len == 0 {
            return Err(ENOMEM);
        }
        self.allocate_output_slice(len)
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
        let len = len.min(self.free::<T>());
        if len == 0 {
            return Err(ENOMEM);
        }
        self.allocate_inout_slice(len)
    }
}

/// Something that can be staged in stage phase.
pub trait Stage<'a> {
    type Item;

    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item>;
}

impl Stage<'_> for () {
    type Item = ();

    #[inline]
    fn stage(self, _: &mut impl Allocator) -> Result<Self::Item> {
        Ok(())
    }
}

/// Allocator in commit phase.
pub trait Committer: phase::Alloc {}

/// Something that can be committed in commit phase.
pub trait Commit {
    type Item;

    fn commit(self, com: &impl Committer) -> Self::Item;
}

impl Commit for () {
    type Item = ();

    #[inline]
    fn commit(self, _: &impl Committer) {}
}

/// Allocator in collection phase.
pub trait Collector: phase::Alloc {}

/// Something that can be collected in collection phase.
pub trait Collect {
    type Item;

    fn collect(self, col: &impl Collector) -> Self::Item;
}
