// SPDX-License-Identifier: Apache-2.0

use super::*;
use x86_64::structures::paging::{
    frame::PhysFrame,
    page::{Page, Size1GiB, Size2MiB, Size4KiB},
    page_table::{FrameError, PageTable, PageTableEntry, PageTableFlags},
    FrameAllocator,
};

/// A Mapper implementation that relies on a PhysAddr to VirtAddr conversion function.
///
/// This type requires that the all physical page table frames are mapped to some virtual
/// address. Normally, this is done by mapping the complete physical address space into
/// the virtual address space at some offset. Other mappings between physical and virtual
/// memory are possible too, as long as they can be calculated as an `PhysAddr` to
/// `VirtAddr` closure.
#[derive(Debug)]
pub struct MappedPageTable<'a, P: PhysToVirt> {
    page_table_walker: PageTableWalker<P>,
    level_4_table: &'a mut PageTable,
}

impl<'a, P: PhysToVirt> MappedPageTable<'a, P> {
    /// Creates a new `MappedPageTable` that uses the passed closure for converting virtual
    /// to physical addresses.
    ///
    /// # Safety
    ///
    /// This function is unsafe because the caller must guarantee that the passed `phys_to_virt`
    /// closure is correct. Also, the passed `level_4_table` must point to the level 4 page table
    /// of a valid page table hierarchy. Otherwise this function might break memory safety, e.g.
    /// by writing to an illegal memory location.
    pub unsafe fn new(level_4_table: &'a mut PageTable, phys_to_virt: P) -> Self {
        Self {
            level_4_table,
            page_table_walker: PageTableWalker::new(phys_to_virt),
        }
    }

    /// Helper function for implementing Mapper. Safe to limit the scope of unsafe, see
    /// https://github.com/rust-lang/rfcs/pull/2585.
    fn map_to_1gib<A>(
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
        let p4 = &mut self.level_4_table;
        let p3 = self.page_table_walker.create_next_table(
            &mut p4[page.p4_index()],
            flags & p321_insert_flag_mask,
            allocator,
        )?;

        if !p3[page.p3_index()].is_unused() {
            return Err(MapToError::PageAlreadyMapped(frame));
        }
        p3[page.p3_index()].set_addr(frame.start_address(), flags | PageTableFlags::HUGE_PAGE);

        Ok(MapperFlush::new(page))
    }

    /// Helper function for implementing Mapper. Safe to limit the scope of unsafe, see
    /// https://github.com/rust-lang/rfcs/pull/2585.
    fn map_to_2mib<A>(
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
        let p4 = &mut self.level_4_table;
        let p3 = self.page_table_walker.create_next_table(
            &mut p4[page.p4_index()],
            flags & p321_insert_flag_mask,
            allocator,
        )?;
        let p2 = self.page_table_walker.create_next_table(
            &mut p3[page.p3_index()],
            flags & p321_insert_flag_mask,
            allocator,
        )?;

        if !p2[page.p2_index()].is_unused() {
            return Err(MapToError::PageAlreadyMapped(frame));
        }
        p2[page.p2_index()].set_addr(frame.start_address(), flags | PageTableFlags::HUGE_PAGE);

        Ok(MapperFlush::new(page))
    }

    /// Helper function for implementing Mapper. Safe to limit the scope of unsafe, see
    /// https://github.com/rust-lang/rfcs/pull/2585.
    fn map_to_4kib<A>(
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
        let p4 = &mut self.level_4_table;
        let p3 = self.page_table_walker.create_next_table(
            &mut p4[page.p4_index()],
            flags & p321_insert_flag_mask,
            allocator,
        )?;
        let p2 = self.page_table_walker.create_next_table(
            &mut p3[page.p3_index()],
            flags & p321_insert_flag_mask,
            allocator,
        )?;
        let p1 = self.page_table_walker.create_next_table(
            &mut p2[page.p2_index()],
            flags & p321_insert_flag_mask,
            allocator,
        )?;

        if !p1[page.p1_index()].is_unused() {
            return Err(MapToError::PageAlreadyMapped(frame));
        }
        p1[page.p1_index()].set_frame(frame.frame(), flags);

        Ok(MapperFlush::new(page))
    }
}

impl<'a, P: PhysToVirt> Mapper<Size1GiB> for MappedPageTable<'a, P> {
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
        self.map_to_1gib(page, frame, flags, p321_insert_flag_mask, allocator)
    }

    fn unmap(
        &mut self,
        page: Page<Size1GiB>,
    ) -> Result<(PhysFrame<Size1GiB>, MapperFlush<Size1GiB>), UnmapError> {
        let p4 = &mut self.level_4_table;
        let p3 = self
            .page_table_walker
            .next_table_mut(&mut p4[page.p4_index()])?;

        let p3_entry = &mut p3[page.p3_index()];
        let flags = p3_entry.flags();

        if !flags.contains(PageTableFlags::PRESENT) {
            return Err(UnmapError::PageNotMapped);
        }
        if !flags.contains(PageTableFlags::HUGE_PAGE) {
            return Err(UnmapError::ParentEntryHugePage);
        }

        let frame = PhysFrame::from_start_address(p3_entry.addr())
            .map_err(|()| UnmapError::InvalidFrameAddress(p3_entry.addr()))?;

        p3_entry.set_unused();
        Ok((frame, MapperFlush::new(page)))
    }

    fn update_flags(
        &mut self,
        page: Page<Size1GiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<Size1GiB>, FlagUpdateError> {
        let p4 = &mut self.level_4_table;
        let p3 = self
            .page_table_walker
            .next_table_mut(&mut p4[page.p4_index()])?;

        if p3[page.p3_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }
        p3[page.p3_index()].set_flags(flags | PageTableFlags::HUGE_PAGE);

        Ok(MapperFlush::new(page))
    }

    fn translate_page(&self, page: Page<Size1GiB>) -> Result<PhysFrame<Size1GiB>, TranslateError> {
        let p4 = &self.level_4_table;
        let p3 = self.page_table_walker.next_table(&p4[page.p4_index()])?;

        let p3_entry = &p3[page.p3_index()];

        if p3_entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        PhysFrame::from_start_address(p3_entry.addr())
            .map_err(|()| TranslateError::InvalidFrameAddress(p3_entry.addr()))
    }
}

impl<'a, P: PhysToVirt> Mapper<Size2MiB> for MappedPageTable<'a, P> {
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
        self.map_to_2mib(page, frame, flags, p321_insert_flag_mask, allocator)
    }

    fn unmap(
        &mut self,
        page: Page<Size2MiB>,
    ) -> Result<(PhysFrame<Size2MiB>, MapperFlush<Size2MiB>), UnmapError> {
        let p4 = &mut self.level_4_table;
        let p3 = self
            .page_table_walker
            .next_table_mut(&mut p4[page.p4_index()])?;
        let p2 = self
            .page_table_walker
            .next_table_mut(&mut p3[page.p3_index()])?;

        let p2_entry = &mut p2[page.p2_index()];
        let flags = p2_entry.flags();

        if !flags.contains(PageTableFlags::PRESENT) {
            return Err(UnmapError::PageNotMapped);
        }
        if !flags.contains(PageTableFlags::HUGE_PAGE) {
            return Err(UnmapError::ParentEntryHugePage);
        }

        let frame = PhysFrame::from_start_address(p2_entry.addr())
            .map_err(|()| UnmapError::InvalidFrameAddress(p2_entry.addr()))?;

        p2_entry.set_unused();
        Ok((frame, MapperFlush::new(page)))
    }

    fn update_flags(
        &mut self,
        page: Page<Size2MiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<Size2MiB>, FlagUpdateError> {
        let p4 = &mut self.level_4_table;
        let p3 = self
            .page_table_walker
            .next_table_mut(&mut p4[page.p4_index()])?;
        let p2 = self
            .page_table_walker
            .next_table_mut(&mut p3[page.p3_index()])?;

        if p2[page.p2_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p2[page.p2_index()].set_flags(flags | PageTableFlags::HUGE_PAGE);

        Ok(MapperFlush::new(page))
    }

    fn translate_page(&self, page: Page<Size2MiB>) -> Result<PhysFrame<Size2MiB>, TranslateError> {
        let p4 = &self.level_4_table;
        let p3 = self.page_table_walker.next_table(&p4[page.p4_index()])?;
        let p2 = self.page_table_walker.next_table(&p3[page.p3_index()])?;

        let p2_entry = &p2[page.p2_index()];

        if p2_entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        PhysFrame::from_start_address(p2_entry.addr())
            .map_err(|()| TranslateError::InvalidFrameAddress(p2_entry.addr()))
    }
}

impl<'a, P: PhysToVirt> Mapper<Size4KiB> for MappedPageTable<'a, P> {
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
        self.map_to_4kib(page, frame, flags, p321_insert_flag_mask, allocator)
    }

    fn unmap(
        &mut self,
        page: Page<Size4KiB>,
    ) -> Result<(PhysFrame<Size4KiB>, MapperFlush<Size4KiB>), UnmapError> {
        let p4 = &mut self.level_4_table;
        let p3 = self
            .page_table_walker
            .next_table_mut(&mut p4[page.p4_index()])?;
        let p2 = self
            .page_table_walker
            .next_table_mut(&mut p3[page.p3_index()])?;
        let p1 = self
            .page_table_walker
            .next_table_mut(&mut p2[page.p2_index()])?;

        let p1_entry = &mut p1[page.p1_index()];

        let frame = p1_entry.frame().map_err(|err| match err {
            FrameError::FrameNotPresent => UnmapError::PageNotMapped,
            FrameError::HugeFrame => UnmapError::ParentEntryHugePage,
        })?;

        p1_entry.set_unused();
        Ok((frame, MapperFlush::new(page)))
    }

    fn update_flags(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<Size4KiB>, FlagUpdateError> {
        let p4 = &mut self.level_4_table;
        let p3 = self
            .page_table_walker
            .next_table_mut(&mut p4[page.p4_index()])?;
        let p2 = self
            .page_table_walker
            .next_table_mut(&mut p3[page.p3_index()])?;
        let p1 = self
            .page_table_walker
            .next_table_mut(&mut p2[page.p2_index()])?;

        if p1[page.p1_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p1[page.p1_index()].set_flags(flags);

        Ok(MapperFlush::new(page))
    }

    fn translate_page(&self, page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, TranslateError> {
        let p4 = &self.level_4_table;
        let p3 = self.page_table_walker.next_table(&p4[page.p4_index()])?;
        let p2 = self.page_table_walker.next_table(&p3[page.p3_index()])?;
        let p1 = self.page_table_walker.next_table(&p2[page.p2_index()])?;

        let p1_entry = &p1[page.p1_index()];

        if p1_entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        PhysFrame::from_start_address(p1_entry.addr())
            .map_err(|()| TranslateError::InvalidFrameAddress(p1_entry.addr()))
    }
}

impl<'a, P: PhysToVirt> MapperAllSizes for MappedPageTable<'a, P> {
    fn translate(&self, addr: VirtAddr) -> TranslateResult {
        let p4 = &self.level_4_table;
        let p3 = match self.page_table_walker.next_table(&p4[addr.p4_index()]) {
            Ok(page_table) => page_table,
            Err(PageTableWalkError::NotMapped) => return TranslateResult::PageNotMapped,
            Err(PageTableWalkError::MappedToHugePage) => {
                panic!("level 4 entry has huge page bit set")
            }
        };
        let p2 = match self.page_table_walker.next_table(&p3[addr.p3_index()]) {
            Ok(page_table) => page_table,
            Err(PageTableWalkError::NotMapped) => return TranslateResult::PageNotMapped,
            Err(PageTableWalkError::MappedToHugePage) => {
                let frame = PhysFrame::containing_address(p3[addr.p3_index()].addr());
                let offset = addr.as_u64() & 0o7_777_777_777;
                return TranslateResult::Frame1GiB { frame, offset };
            }
        };
        let p1 = match self.page_table_walker.next_table(&p2[addr.p2_index()]) {
            Ok(page_table) => page_table,
            Err(PageTableWalkError::NotMapped) => return TranslateResult::PageNotMapped,
            Err(PageTableWalkError::MappedToHugePage) => {
                let frame = PhysFrame::containing_address(p2[addr.p2_index()].addr());
                let offset = addr.as_u64() & 0o7_777_777;
                return TranslateResult::Frame2MiB { frame, offset };
            }
        };

        let p1_entry = &p1[addr.p1_index()];

        if p1_entry.is_unused() {
            return TranslateResult::PageNotMapped;
        }

        let frame = match PhysFrame::from_start_address(p1_entry.addr()) {
            Ok(frame) => frame,
            Err(()) => return TranslateResult::InvalidFrameAddress(p1_entry.addr()),
        };
        let offset = u64::from(addr.page_offset());
        TranslateResult::Frame4KiB { frame, offset }
    }
}

#[derive(Debug)]
struct PageTableWalker<P: PhysToVirt> {
    phys_to_virt: P,
}

impl<P: PhysToVirt> PageTableWalker<P> {
    pub unsafe fn new(phys_to_virt: P) -> Self {
        Self { phys_to_virt }
    }

    /// Internal helper function to get a reference to the page table of the next level.
    ///
    /// Returns `PageTableWalkError::NotMapped` if the entry is unused. Returns
    /// `PageTableWalkError::MappedToHugePage` if the `HUGE_PAGE` flag is set
    /// in the passed entry.
    fn next_table<'b>(
        &self,
        entry: &'b PageTableEntry,
    ) -> Result<&'b PageTable, PageTableWalkError> {
        let page_table_ptr = self.phys_to_virt.phys_to_virt(entry.frame()?);
        let page_table: &PageTable = unsafe { &*page_table_ptr };

        Ok(page_table)
    }

    /// Internal helper function to get a mutable reference to the page table of the next level.
    ///
    /// Returns `PageTableWalkError::NotMapped` if the entry is unused. Returns
    /// `PageTableWalkError::MappedToHugePage` if the `HUGE_PAGE` flag is set
    /// in the passed entry.
    fn next_table_mut<'b>(
        &self,
        entry: &'b mut PageTableEntry,
    ) -> Result<&'b mut PageTable, PageTableWalkError> {
        let page_table_ptr = self.phys_to_virt.phys_to_virt(entry.frame()?);
        let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

        Ok(page_table)
    }

    /// Internal helper function to create the page table of the next level if needed.
    ///
    /// If the passed entry is unused, a new frame is allocated from the given allocator, zeroed,
    /// and the entry is updated to that address. If the passed entry is already mapped, the next
    /// table is returned directly.
    ///
    /// Returns `MapToError::FrameAllocationFailed` if the entry is unused and the allocator
    /// returned `None`. Returns `MapToError::ParentEntryHugePage` if the `HUGE_PAGE` flag is set
    /// in the passed entry.
    fn create_next_table<'b, A>(
        &self,
        entry: &'b mut PageTableEntry,
        insert_flags: PageTableFlags,
        allocator: &mut A,
    ) -> Result<&'b mut PageTable, PageTableCreateError>
    where
        A: FrameAllocator<Size4KiB>,
    {
        let created;

        if entry.is_unused() {
            if let Some(frame) = allocator.allocate_frame() {
                entry.set_frame(
                    frame.frame(),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE | insert_flags,
                );
                created = true;
            } else {
                return Err(PageTableCreateError::FrameAllocationFailed);
            }
        } else {
            if !insert_flags.is_empty() && !entry.flags().contains(insert_flags) {
                entry.set_flags(entry.flags() | insert_flags);
            }
            created = false;
        }

        let page_table = match self.next_table_mut(entry) {
            Err(PageTableWalkError::MappedToHugePage) => {
                Err(PageTableCreateError::MappedToHugePage)?
            }
            Err(PageTableWalkError::NotMapped) => panic!("entry should be mapped at this point"),
            Ok(page_table) => page_table,
        };

        if created {
            page_table.zero();
        }
        Ok(page_table)
    }
}

#[derive(Debug)]
enum PageTableWalkError {
    NotMapped,
    MappedToHugePage,
}

#[derive(Debug)]
enum PageTableCreateError {
    MappedToHugePage,
    FrameAllocationFailed,
}

impl From<PageTableCreateError> for MapToError<Size4KiB> {
    fn from(err: PageTableCreateError) -> Self {
        match err {
            PageTableCreateError::MappedToHugePage => MapToError::ParentEntryHugePage,
            PageTableCreateError::FrameAllocationFailed => MapToError::FrameAllocationFailed,
        }
    }
}

impl From<PageTableCreateError> for MapToError<Size2MiB> {
    fn from(err: PageTableCreateError) -> Self {
        match err {
            PageTableCreateError::MappedToHugePage => MapToError::ParentEntryHugePage,
            PageTableCreateError::FrameAllocationFailed => MapToError::FrameAllocationFailed,
        }
    }
}

impl From<PageTableCreateError> for MapToError<Size1GiB> {
    fn from(err: PageTableCreateError) -> Self {
        match err {
            PageTableCreateError::MappedToHugePage => MapToError::ParentEntryHugePage,
            PageTableCreateError::FrameAllocationFailed => MapToError::FrameAllocationFailed,
        }
    }
}

impl From<FrameError> for PageTableWalkError {
    fn from(err: FrameError) -> Self {
        match err {
            FrameError::HugeFrame => PageTableWalkError::MappedToHugePage,
            FrameError::FrameNotPresent => PageTableWalkError::NotMapped,
        }
    }
}

impl From<PageTableWalkError> for UnmapError {
    fn from(err: PageTableWalkError) -> Self {
        match err {
            PageTableWalkError::MappedToHugePage => UnmapError::ParentEntryHugePage,
            PageTableWalkError::NotMapped => UnmapError::PageNotMapped,
        }
    }
}

impl From<PageTableWalkError> for FlagUpdateError {
    fn from(err: PageTableWalkError) -> Self {
        match err {
            PageTableWalkError::MappedToHugePage => FlagUpdateError::ParentEntryHugePage,
            PageTableWalkError::NotMapped => FlagUpdateError::PageNotMapped,
        }
    }
}

impl From<PageTableWalkError> for TranslateError {
    fn from(err: PageTableWalkError) -> Self {
        match err {
            PageTableWalkError::MappedToHugePage => TranslateError::ParentEntryHugePage,
            PageTableWalkError::NotMapped => TranslateError::PageNotMapped,
        }
    }
}

/// Trait for converting a physical address to a virtual one.
///
/// This only works if the physical address space is somehow mapped to the virtual
/// address space, e.g. at an offset.
pub trait PhysToVirt {
    /// Translate the given physical frame to a virtual page table pointer.
    fn phys_to_virt(&self, phys_frame: PhysFrame) -> *mut PageTable;
}

impl<T> PhysToVirt for T
where
    T: Fn(PhysFrame) -> *mut PageTable,
{
    fn phys_to_virt(&self, phys_frame: PhysFrame) -> *mut PageTable {
        self(phys_frame)
    }
}
