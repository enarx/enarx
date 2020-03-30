// SPDX-License-Identifier: Apache-2.0

#![cfg(target_arch = "x86_64")]

use super::*;
use x86_64::structures::paging::{frame::PhysFrame, page_table::PageTable, FrameAllocator};

/// A Mapper implementation that requires that the complete physically memory is mapped at some
/// offset in the virtual address space.
#[derive(Debug)]
pub struct OffsetPageTable<'a> {
    inner: MappedPageTable<'a, PhysOffset>,
}

impl<'a> OffsetPageTable<'a> {
    /// Creates a new `OffsetPageTable` that uses the given offset for converting virtual
    /// to physical addresses.
    ///
    /// The complete physical memory must be mapped in the virtual address space starting at
    /// address `phys_offset`. This means that for example physical address `0x5000` can be
    /// accessed through virtual address `phys_offset + 0x5000`. This mapping is required because
    /// the mapper needs to access page tables, which are not mapped into the virtual address
    /// space by default.
    ///
    /// # Safety
    ///
    /// This function is unsafe because the caller must guarantee that the passed `phys_offset`
    /// is correct. Also, the passed `level_4_table` must point to the level 4 page table
    /// of a valid page table hierarchy. Otherwise this function might break memory safety, e.g.
    /// by writing to an illegal memory location.
    pub unsafe fn new(level_4_table: &'a mut PageTable, phys_offset: VirtAddr) -> Self {
        let phys_offset = PhysOffset {
            offset: phys_offset,
        };
        Self {
            inner: MappedPageTable::new(level_4_table, phys_offset),
        }
    }
}

#[derive(Debug)]
struct PhysOffset {
    offset: VirtAddr,
}

impl PhysToVirt for PhysOffset {
    fn phys_to_virt(&self, frame: PhysFrame) -> *mut PageTable {
        let phys = frame.start_address().as_u64();
        let virt = self.offset + phys;
        virt.as_mut_ptr()
    }
}

// delegate all trait implementations to inner

impl<'a> Mapper<Size1GiB> for OffsetPageTable<'a> {
    fn map_to<A>(
        &mut self,
        page: Page<Size1GiB>,
        frame: UnusedPhysFrame<Size1GiB>,
        flags: PageTableFlags,
        p321_insert_flag_mask: PageTableFlags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size1GiB>, MapToError<Size1GiB>>
    where
        A: FrameAllocator<Size4KiB>,
    {
        self.inner
            .map_to(page, frame, flags, p321_insert_flag_mask, allocator)
    }

    fn unmap(
        &mut self,
        page: Page<Size1GiB>,
    ) -> Result<(PhysFrame<Size1GiB>, MapperFlush<Size1GiB>), UnmapError> {
        self.inner.unmap(page)
    }

    fn update_flags(
        &mut self,
        page: Page<Size1GiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<Size1GiB>, FlagUpdateError> {
        self.inner.update_flags(page, flags)
    }

    fn translate_page(&self, page: Page<Size1GiB>) -> Result<PhysFrame<Size1GiB>, TranslateError> {
        self.inner.translate_page(page)
    }
}

impl<'a> Mapper<Size2MiB> for OffsetPageTable<'a> {
    fn map_to<A>(
        &mut self,
        page: Page<Size2MiB>,
        frame: UnusedPhysFrame<Size2MiB>,
        flags: PageTableFlags,
        p321_insert_flag_mask: PageTableFlags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size2MiB>, MapToError<Size2MiB>>
    where
        A: FrameAllocator<Size4KiB>,
    {
        self.inner
            .map_to(page, frame, flags, p321_insert_flag_mask, allocator)
    }

    fn unmap(
        &mut self,
        page: Page<Size2MiB>,
    ) -> Result<(PhysFrame<Size2MiB>, MapperFlush<Size2MiB>), UnmapError> {
        self.inner.unmap(page)
    }

    fn update_flags(
        &mut self,
        page: Page<Size2MiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<Size2MiB>, FlagUpdateError> {
        self.inner.update_flags(page, flags)
    }

    fn translate_page(&self, page: Page<Size2MiB>) -> Result<PhysFrame<Size2MiB>, TranslateError> {
        self.inner.translate_page(page)
    }
}

impl<'a> Mapper<Size4KiB> for OffsetPageTable<'a> {
    fn map_to<A>(
        &mut self,
        page: Page<Size4KiB>,
        frame: UnusedPhysFrame<Size4KiB>,
        flags: PageTableFlags,
        p321_insert_flag_mask: PageTableFlags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>>
    where
        A: FrameAllocator<Size4KiB>,
    {
        self.inner
            .map_to(page, frame, flags, p321_insert_flag_mask, allocator)
    }

    fn unmap(
        &mut self,
        page: Page<Size4KiB>,
    ) -> Result<(PhysFrame<Size4KiB>, MapperFlush<Size4KiB>), UnmapError> {
        self.inner.unmap(page)
    }

    fn update_flags(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<Size4KiB>, FlagUpdateError> {
        self.inner.update_flags(page, flags)
    }

    fn translate_page(&self, page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, TranslateError> {
        self.inner.translate_page(page)
    }
}

impl<'a> MapperAllSizes for OffsetPageTable<'a> {
    fn translate(&self, addr: VirtAddr) -> TranslateResult {
        self.inner.translate(addr)
    }
}
