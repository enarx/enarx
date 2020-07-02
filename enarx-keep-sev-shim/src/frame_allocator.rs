// SPDX-License-Identifier: Apache-2.0

//! The global FrameAllocator
use crate::rwlock_singleton;
use enarx_keep_sev_shim::BootInfo;
use memory::Page as Page4KiB;
use memory::{Address, Offset};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageSize, PageTableFlags, PhysFrame, Size2MiB, Size4KiB,
};
use x86_64::{align_down, PhysAddr, VirtAddr};

/// An aligned 2MiB Page
///
/// The `x86_64::structures::paging::Page<S>` is not aligned, so we use
/// memory::Page as Page4KiB and this Page2MiB
#[derive(Copy, Clone)]
#[repr(C, align(2097152))]
pub struct Page2MiB([u8; 2097152]);

rwlock_singleton! {
    static mut FRAME_ALLOCATOR: ShimFrameAllocatorRWLock<ShimFrameAllocator>;
}

impl ShimFrameAllocatorRWLock {
    /// Initialize the FrameAllocator from the passed `BootInfo`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because the caller must guarantee,
    /// that the passed `BootInfo` is valid.
    ///
    /// Should be only called once.
    pub unsafe fn init(boot_info: &BootInfo) {
        let start = Address::from(boot_info.code.end);
        let frame_allocator = ShimFrameAllocator {
            max: boot_info.mem_size,
            next_4k: start.raise(),
            next_2M: start.raise(),
        };
        ShimFrameAllocatorRWLock::init_global(frame_allocator);
    }
}

/// A frame allocator
#[allow(non_snake_case)]
pub struct ShimFrameAllocator {
    max: usize,
    next_4k: Address<usize, Page4KiB>,
    next_2M: Address<usize, Page2MiB>,
}

impl core::fmt::Debug for ShimFrameAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("ShimFrameAllocator")
            .field("max   ", &format_args!("{:#?}", self.max as *const u8))
            .field(
                "next4k",
                &format_args!("{:#?}", self.next_4k.raw() as *const u8),
            )
            .field(
                "next2M",
                &format_args!("{:#?}", self.next_2M.raw() as *const u8),
            )
            .finish()
    }
}

impl ShimFrameAllocator {
    #[inline(always)]
    fn do_allocate_and_map_memory<S: PageSize>(
        frame_allocator: &mut (impl FrameAllocator<S> + FrameAllocator<Size4KiB>),
        map_to: &[Page<S>],
        mapper: &mut impl Mapper<S>,
        flags: PageTableFlags,
        parent_flags: PageTableFlags,
    ) -> Result<(), ()> {
        if map_to.is_empty() {
            return Ok(());
        }
        let size = map_to
            .len()
            .checked_mul(Page::<S>::SIZE as usize)
            .ok_or(())?;

        let page_range = {
            let start = VirtAddr::from_ptr(map_to.as_ptr());
            let end = start + size - 1u64;
            let start_page = Page::<S>::containing_address(start);
            let end_page = Page::<S>::containing_address(end);
            Page::range_inclusive(start_page, end_page)
        };

        for page in page_range {
            let frame = frame_allocator.allocate_frame().ok_or(())?;

            unsafe {
                mapper
                    .map_to_with_table_flags(page, frame, flags, parent_flags, frame_allocator)
                    .map_err(|_| ())?
                    .flush();
            }
        }
        Ok(())
    }

    /// Allocate memory and map it to the given virtual address
    pub fn allocate_and_map_memory(
        &mut self,
        mapper: &mut (impl Mapper<Size4KiB> + Mapper<Size2MiB>),
        map_to: VirtAddr,
        size: usize,
        flags: PageTableFlags,
        parent_flags: PageTableFlags,
    ) -> Result<&'static mut [u8], ()> {
        if size == 0 {
            return Err(());
        }

        if !map_to.is_aligned(Page::<Size4KiB>::SIZE) {
            return Err(());
        }

        if size != align_down(size as _, Page::<Size4KiB>::SIZE) as usize {
            return Err(());
        }

        let slice = unsafe {
            core::slice::from_raw_parts_mut(
                map_to.as_mut_ptr::<Page4KiB>(),
                size.checked_div(Page4KiB::size()).ok_or(())?,
            )
        };

        // Find the best mix of 4KiB and 2MiB Pages
        let (pre, middle, post) = unsafe { slice.align_to_mut::<Page2MiB>() };

        let pre: &mut [Page<Size4KiB>] =
            unsafe { core::slice::from_raw_parts_mut(pre.as_mut_ptr() as *mut Page, pre.len()) };

        let middle: &[Page<Size2MiB>] = unsafe {
            core::slice::from_raw_parts(middle.as_ptr() as *const Page<Size2MiB>, middle.len())
        };

        let post: &[Page<Size4KiB>] = unsafe {
            core::slice::from_raw_parts(post.as_ptr() as *const Page<Size4KiB>, post.len())
        };

        // Allocate the mix of 4KiB and 2MiB Pages
        ShimFrameAllocator::do_allocate_and_map_memory(self, &pre, mapper, flags, parent_flags)?;
        ShimFrameAllocator::do_allocate_and_map_memory(self, &middle, mapper, flags, parent_flags)?;
        ShimFrameAllocator::do_allocate_and_map_memory(self, &post, mapper, flags, parent_flags)?;

        // transmute the whole thing to one big bytes slice
        Ok(unsafe { core::slice::from_raw_parts_mut(pre.as_mut_ptr() as *mut u8, size) })
    }

    /// Map physical memory to the given virtual address
    pub fn map_memory(
        &mut self,
        mapper: &mut (impl Mapper<Size4KiB> + Mapper<Size2MiB>),
        map_from: PhysAddr,
        map_to: VirtAddr,
        size: usize,
        flags: PageTableFlags,
        parent_flags: PageTableFlags,
    ) -> Result<(), ()> {
        if size == 0 {
            return Err(());
        }

        let frame_range_from = {
            let start = map_from;
            let end = start + size - 1u64;
            let start_frame = PhysFrame::<Size4KiB>::containing_address(start);
            let end_frame = PhysFrame::<Size4KiB>::containing_address(end);
            PhysFrame::range_inclusive(start_frame, end_frame)
        };

        let page_range_to = {
            let start = map_to;
            let end = start + size - 1u64;
            let start_page = Page::<Size4KiB>::containing_address(start);
            let end_page = Page::<Size4KiB>::containing_address(end);
            Page::range_inclusive(start_page, end_page)
        };

        for (frame_from, page_to) in frame_range_from.zip(page_range_to) {
            unsafe {
                mapper
                    .map_to_with_table_flags(page_to, frame_from, flags, parent_flags, self)
                    .map_err(|_| ())?
                    .flush();
            }
        }

        Ok(())
    }
}

unsafe impl FrameAllocator<Size4KiB> for ShimFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame_address = self.next_4k;
        self.next_4k += Offset::from_items(1);

        // if at the start of a 2MiB page, advance to the next free 2MiB
        if self.next_4k.raw() == self.next_4k.raise::<Page2MiB>().raw() {
            self.next_4k = self.next_2M.raise();
        }

        if frame_address.raw() >= self.next_2M.raw() {
            // we have taken a bite out of the next 2MiB page
            // so advance the 2MiB pointer
            self.next_2M += Offset::from_items(1);
        }

        if self.next_4k.raw() > self.max {
            // OOM
            return None;
        }

        Some(PhysFrame::containing_address(PhysAddr::new(
            frame_address.raw() as _,
        )))
    }
}

unsafe impl FrameAllocator<Size2MiB> for ShimFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let frame_address = self.next_2M;
        self.next_2M += Offset::from_items(1);

        if self.next_2M.raw() > self.max {
            // OOM
            return None;
        }

        Some(PhysFrame::containing_address(PhysAddr::new(
            frame_address.raw() as _,
        )))
    }
}
