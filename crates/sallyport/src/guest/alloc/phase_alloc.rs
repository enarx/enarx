// SPDX-License-Identifier: Apache-2.0

use super::{Allocator, Collector, Committer, InOutRef, InRef, OutRef};
use crate::libc::{EFAULT, ENOMEM, EOVERFLOW};
use crate::Result;

use core::alloc::Layout;
use core::marker::PhantomData;
use core::mem::{align_of, size_of, size_of_val};
use core::ptr::NonNull;

pub(crate) mod phase {
    #[repr(transparent)]
    pub struct Init;

    #[repr(transparent)]
    pub struct Stage;
    #[repr(transparent)]
    pub struct Commit;
    #[repr(transparent)]
    pub struct Collect;

    pub trait Alloc {}
}

#[derive(Debug)]
pub struct Alloc<'a, Phase> {
    /// Write-only pointer to memory location, where next object will be allocated.
    pub(crate) ptr: NonNull<[u8]>,
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
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
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
            offset: self.offset,

            phase: PhantomData,
        }
    }
}

impl<'a> Alloc<'a, phase::Stage> {
    /// Allocates a memory region of `layout.size()` bytes with padding required to ensure
    /// alignment and returns a tuple of non-null pointer and byte offset of start of that aligned
    /// region on success.
    #[inline]
    fn allocate_layout(&mut self, layout: Layout) -> Result<(NonNull<[u8]>, usize)> {
        let free = self.ptr.len();
        let pad_size = self.ptr.cast::<u8>().as_ptr().align_offset(layout.align());
        let layout_size = layout.size();

        if free < pad_size.checked_add(layout_size).ok_or(EOVERFLOW)? {
            return Err(ENOMEM);
        }

        let raw_slice = self.ptr.as_ptr();

        // SAFETY: we know raw_slice is nonnull, and we know pad_size is in-bounds
        let padded_raw_slice = unsafe { raw_slice.get_unchecked_mut(pad_size..) };

        // SAFETY: we know padded_raw_slice is nonnull, and we know layout_size is in-bounds
        let new_region = unsafe { padded_raw_slice.get_unchecked_mut(..layout_size) };

        // SAFETY: we know padded_raw_slice is nonnull, and we know layout_size is in-bounds
        let remainder = unsafe { padded_raw_slice.get_unchecked_mut(layout_size..) };

        let offset = self.offset + pad_size;

        *self = Self {
            // SAFETY: we know remainder is nonnull
            ptr: unsafe { NonNull::new_unchecked(remainder) },
            offset: offset + layout_size,
            phase: PhantomData,
        };

        // SAFETY: we know new_region is nonnull
        Ok((unsafe { NonNull::new_unchecked(new_region) }, offset))
    }

    #[inline]
    fn reserve_layout<T>(
        &mut self,
        layout: Layout,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<(T, NonNull<[u8]>, usize)> {
        let layout_size = layout.size();
        let free = self.ptr.len().checked_sub(layout_size).ok_or(ENOMEM)?;

        let align = layout.align();
        // NOTE: `align_offset` computes offset to the next aligned address, but we need the offset to the previous aligned address.
        let pad_size =
            unsafe { self.ptr.cast::<u8>().as_ptr().add(free) }.align_offset(align) % align;
        let free = free.checked_sub(pad_size).ok_or(ENOMEM)?;

        let mut alloc = Self {
            ptr: NonNull::slice_from_raw_parts(self.ptr.cast(), free),
            offset: self.offset,

            phase: PhantomData,
        };
        let data = f(&mut alloc)?;
        alloc.ptr = NonNull::slice_from_raw_parts(
            alloc.ptr.cast(),
            alloc.ptr.len() + pad_size + layout_size,
        );
        let (ptr, offset) = alloc.allocate_layout(layout)?;
        *self = alloc;
        Ok((data, ptr, offset))
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
    fn reserve_input_layout<'b, T, F>(
        &mut self,
        layout: Layout,
        f: F,
    ) -> Result<(T, InRef<'b, [u8]>)>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        self.reserve_layout(layout, f)
            .map(|(data, ptr, offset)| (data, InRef::new(ptr, offset)))
    }

    #[inline]
    fn reserve_output_layout<'b, T, F>(
        &mut self,
        layout: Layout,
        f: F,
    ) -> Result<(T, OutRef<'b, [u8]>)>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        self.reserve_layout(layout, f)
            .map(|(data, ptr, offset)| (data, OutRef::new(ptr, offset)))
    }

    #[inline]
    fn reserve_inout_layout<'b, T, F>(
        &mut self,
        layout: Layout,
        f: F,
    ) -> Result<(T, InOutRef<'b, [u8]>)>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        self.reserve_layout(layout, f)
            .map(|(data, ptr, offset)| (data, InOutRef::new(ptr, offset)))
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

impl<'a> Alloc<'a, phase::Commit> {
    /// Releases the ownership of the underlying sallyport block and returns a closure, which can
    /// be used to transition the allocator into collection phase given an immutable borrow of a
    /// block after successful execution of its' contents by the host.
    /// The returned closure fails if the passed slice does not refer to the same memory region as
    /// the underlying sallyport block used in previous phases.
    #[inline]
    pub fn sally<'b: 'a>(self) -> impl FnOnce(&'b [usize]) -> Result<Alloc<'b, phase::Collect>> {
        let ptr = self.ptr;
        let offset = self.offset;
        move |block| {
            debug_assert_eq!(
                block.as_ptr(),
                unsafe { ptr.cast::<u8>().as_ptr().sub(offset) } as _
            );
            debug_assert!(size_of_val(block) >= offset);

            if block.as_ptr() != unsafe { ptr.cast::<u8>().as_ptr().sub(offset) } as _
                || size_of_val(block) < offset
            {
                Err(EFAULT)
            } else {
                Ok(Alloc {
                    ptr,
                    offset,

                    phase: PhantomData,
                })
            }
        }
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
