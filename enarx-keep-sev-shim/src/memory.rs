// SPDX-License-Identifier: Apache-2.0

use crate::arch::x86_64::{
    structures::paging::{FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};
use vmsyscall::memory_map::{Map, RegionType};
use x86_64::structures::paging::UnusedPhysFrame;

/// Initialize a new OffsetPageTable.
///
/// This function is unsafe because the caller must guarantee that the
/// complete physical memory is mapped to virtual memory at the passed
/// `physical_memory_offset`. Also, this function must be only called once
/// to avoid aliasing `&mut` references (which is undefined behavior).
///
/// # Safety
/// FIXME
///
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = active_level_4_table(physical_memory_offset);
    OffsetPageTable::new(level_4_table, physical_memory_offset)
}

/// Returns a mutable reference to the active level 4 table.
///
/// This function is unsafe because the caller must guarantee that the
/// complete physical memory is mapped to virtual memory at the passed
/// `physical_memory_offset`. Also, this function must be only called once
/// to avoid aliasing `&mut` references (which is undefined behavior).
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();

    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table_ptr // unsafe
}

/// A FrameAllocator that returns usable frames from the bootloader's memory map.
#[derive(Debug)]
pub struct BootInfoFrameAllocator {
    memory_map: Map,
    next: usize,
}

impl BootInfoFrameAllocator {
    /// Create a FrameAllocator from the passed memory map.
    ///
    /// This function is unsafe because the caller must guarantee that the passed
    /// memory map is valid. The main requirement is that all frames that are marked
    /// as `USABLE` in it are really unused.
    ///
    /// # Safety
    /// FIXME
    pub unsafe fn init(memory_map: Map) -> Self {
        BootInfoFrameAllocator {
            memory_map,
            next: 0,
        }
    }

    pub fn set_region_type_usable(&mut self, region_type: RegionType) {
        self.memory_map.iter_mut().for_each(|r| {
            if r.region_type == region_type {
                r.region_type = RegionType::Usable
            }
        });
    }

    /// Returns an iterator over the usable frames specified in the memory map.
    fn usable_frames(&self) -> impl Iterator<Item = UnusedPhysFrame> + '_ {
        // get usable regions from memory map
        let regions = self.memory_map.iter();
        let usable_regions = regions.filter(|r| {
            r.region_type == RegionType::Usable || r.region_type == RegionType::Bootloader
        });
        // map each region to its address range
        let addr_ranges = usable_regions.map(|r| r.range.start_addr()..r.range.end_addr());
        // transform to an iterator of frame start addresses
        let frame_addresses = addr_ranges.flat_map(|r| r.step_by(4096));
        // create `PhysFrame` types from the start addresses
        let frames = frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)));
        // we know that the frames are really unused
        frames.map(|f| unsafe { UnusedPhysFrame::new(f) })
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<UnusedPhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}

/* FIXME:
impl FrameDeallocator<Size4KiB> for BootInfoFrameAllocator {
    fn deallocate_frame(&mut self, frame: UnusedPhysFrame<Size4KiB>) {
        self.memory_map.add_region(Region {
            range: FrameRange::new(
                frame.start_address().as_u64(),
                frame.start_address().as_u64() + frame.size() - 1,
            ),
            region_type: RegionType::Usable,
        })
    }
}
*/
