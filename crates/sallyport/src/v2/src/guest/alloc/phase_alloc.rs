// SPDX-License-Identifier: Apache-2.0

use super::{Allocator, Collector, Committer, InOutRef, InRef, OutRef};
use crate::Result;

use core::alloc::Layout;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::addr_of_mut;
use core::ptr::NonNull;
use libc::{ENOMEM, EOVERFLOW};

pub(crate) mod phase {
    pub struct Init(());

    pub struct Stage(());
    pub struct Commit(());
    pub struct Collect(());

    pub trait Alloc {}
}

#[derive(Debug)]
pub struct Alloc<'a, Phase> {
    /// Write-only pointer to memory location, where next object will be allocated.
    ptr: NonNull<[u8]>,
    /// Byte offset of the next allocated ptr object within allocation buffer.
    offset: usize,

    phase: PhantomData<&'a Phase>,
}

impl<'a, P> Alloc<'a, P> {
    #[inline]
    fn into_phase<T>(self) -> Alloc<'a, T> {
        Alloc {
            ptr: self.ptr,
            offset: self.offset,

            phase: PhantomData,
        }
    }
}

impl<T> phase::Alloc for Alloc<'_, T> {}

impl<'a> Alloc<'a, phase::Init> {
    /// Constructs and returns a new allocator ready to use.
    #[inline]
    pub fn new(buffer: &'a mut [usize]) -> Self {
        let (prefix, buffer, suffix) = unsafe { buffer.align_to_mut::<u8>() };
        assert!(prefix.is_empty());
        assert!(suffix.is_empty());
        Self {
            ptr: NonNull::from(buffer),
            offset: 0,

            phase: PhantomData,
        }
    }

    /// Begins allocation by transitioning the allocator into stage phase.
    #[inline]
    pub fn stage(&mut self) -> Alloc<'a, phase::Stage> {
        Alloc {
            ptr: self.ptr,
            offset: 0,

            phase: PhantomData,
        }
    }
}

impl<'a> Alloc<'a, phase::Stage> {
    /// Allocates a memory region of `layout.size()` bytes with padding required to ensure alignment
    /// and returns a tuple of non-null pointer and byte offset of start of that aligned region on success.
    #[inline]
    fn allocate_layout(&mut self, layout: Layout) -> Result<(NonNull<[u8]>, usize)> {
        let free = self.ptr.len();
        let pad_size = self.ptr.cast::<u8>().as_ptr().align_offset(layout.align());
        let layout_size = layout.size();
        if free < pad_size.checked_add(layout_size).ok_or(EOVERFLOW)? {
            return Err(ENOMEM);
        }

        let ptr = unsafe { addr_of_mut!((*(self.ptr.as_ptr()))[pad_size..]) };
        let offset = self.offset + pad_size;
        *self = Self {
            ptr: unsafe { NonNull::new_unchecked(addr_of_mut!((*(ptr))[layout_size..])) },
            offset: offset + layout_size,

            phase: PhantomData,
        };
        Ok((
            unsafe { NonNull::new_unchecked(addr_of_mut!((*(ptr))[..layout_size])) },
            offset,
        ))
    }
}

impl<'a> Allocator for Alloc<'a, phase::Stage> {
    type Committer = Alloc<'a, phase::Commit>;

    #[inline]
    fn free<T>(&self) -> usize {
        let free_bytes = self.ptr.len();
        let pad_size = self.ptr.as_ptr().cast::<u8>().align_offset(align_of::<T>());
        if free_bytes < pad_size {
            0
        } else {
            (free_bytes - pad_size) / size_of::<T>()
        }
    }

    #[inline]
    fn allocate_inout_layout<'b>(&mut self, layout: Layout) -> Result<InOutRef<'b, [u8]>> {
        self.allocate_layout(layout)
            .map(|(ptr, offset)| InOutRef::new(ptr, offset))
    }

    #[inline]
    fn allocate_input_layout<'b>(&mut self, layout: Layout) -> Result<InRef<'b, [u8]>> {
        self.allocate_layout(layout)
            .map(|(ptr, offset)| InRef::new(ptr, offset))
    }

    #[inline]
    fn allocate_output_layout<'b>(&mut self, layout: Layout) -> Result<OutRef<'b, [u8]>> {
        self.allocate_layout(layout)
            .map(|(ptr, offset)| OutRef::new(ptr, offset))
    }

    #[inline]
    fn section<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<(T, usize)> {
        let mut alloc = Self {
            ptr: self.ptr,
            offset: 0,

            phase: PhantomData,
        };
        f(&mut alloc).map(|s| {
            *self = Self {
                ptr: alloc.ptr,
                offset: self.offset + alloc.offset,

                phase: PhantomData,
            };
            (s, alloc.offset)
        })
    }

    #[inline]
    fn commit(self) -> Self::Committer {
        self.into_phase()
    }
}

impl<'a> Committer for Alloc<'a, phase::Commit> {
    type Collector = Alloc<'a, phase::Collect>;

    #[inline]
    fn collect(self) -> Self::Collector {
        self.into_phase()
    }
}

impl<'a> Collector for Alloc<'a, phase::Collect> {}
