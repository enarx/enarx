// SPDX-License-Identifier: Apache-2.0

//! The global FrameAllocator
use crate::addr::{HostVirtAddr, ShimPhysAddr, ShimPhysUnencryptedAddr, ShimVirtAddr};
use crate::hostcall::HOST_CALL;
use crate::lazy::Lazy;
use crate::{get_cbit_mask, BOOT_INFO};

use nbytes::bytes;
use primordial::{Address, Offset, Page as Page4KiB};
use spinning::RwLock;
use x86_64::structures::paging::FrameAllocator as _;
use x86_64::structures::paging::{
    self, Mapper, Page, PageSize, PageTableFlags, PhysFrame, Size2MiB, Size4KiB,
};
use x86_64::{align_down, align_up, PhysAddr, VirtAddr};

/// An aligned 2MiB Page
///
/// The `x86_64::structures::paging::Page<S>` is not aligned, so we use
/// memory::Page as Page4KiB and this Page2MiB
#[derive(Copy, Clone)]
#[repr(C, align(0x200000))]
#[allow(clippy::integer_arithmetic)]
pub struct Page2MiB([u8; bytes![2; MiB]]);

/// The global ShimFrameAllocator RwLock
pub static FRAME_ALLOCATOR: Lazy<RwLock<FrameAllocator>> = Lazy::new(|| {
    RwLock::<FrameAllocator>::const_new(spinning::RawRwLock::const_new(), unsafe {
        FrameAllocator::new()
    })
});

struct FreeMemListPageHeader {
    next: Option<&'static mut FreeMemListPage>,
}

#[derive(Clone, Copy)]
struct FreeMemListPageEntry {
    start: usize,
    end: usize,
    virt_offset: i64,
}

/// Number of memory list entries per page
pub const FREE_MEM_LIST_NUM_ENTRIES: usize = (Page4KiB::size()
    - core::mem::size_of::<FreeMemListPageHeader>())
    / core::mem::size_of::<FreeMemListPageEntry>();

struct FreeMemListPage {
    header: FreeMemListPageHeader,
    ent: [FreeMemListPageEntry; FREE_MEM_LIST_NUM_ENTRIES],
}

/// A frame allocator
pub struct FrameAllocator {
    min_alloc: usize,
    max_alloc: usize,
    free_mem: FreeMemListPage,
    next_page: Address<usize, Page4KiB>,
    next_huge_page: Address<usize, Page2MiB>,
}

impl core::fmt::Debug for FrameAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("FrameAllocator")
            .field("min_alloc", &self.min_alloc)
            .field("max_alloc", &self.max_alloc)
            .field(
                "next_page",
                &format_args!("{:#?}", self.next_page.raw() as *const u8),
            )
            .field(
                "next_huge_page",
                &format_args!("{:#?}", self.next_huge_page.raw() as *const u8),
            )
            .finish()
    }
}

/// Get the most significant bit set
/// Poor man's log2
#[inline]
#[allow(clippy::integer_arithmetic)]
fn msb(val: usize) -> usize {
    let mut val = val;
    let mut r = 0;
    loop {
        val >>= 1;

        if val == 0 {
            return r;
        }

        r += 1;
    }
}

impl FrameAllocator {
    #[allow(clippy::integer_arithmetic)]
    unsafe fn new() -> Self {
        let boot_info = BOOT_INFO.read().unwrap();
        let start = Address::from(boot_info.code.end);
        let mut free_mem = FreeMemListPage {
            header: FreeMemListPageHeader { next: None },
            ent: [FreeMemListPageEntry {
                start: 0,
                end: 0,
                virt_offset: 0,
            }; FREE_MEM_LIST_NUM_ENTRIES],
        };

        let meminfo = {
            let mut host_call = HOST_CALL.try_lock().unwrap();
            host_call.mem_info().unwrap()
        };

        const MIN_EXP: usize = 25; // start with 2^25 = 32 MiB
        const TARGET_EXP: usize = 47; // we want more than 2^47 = 128 TiB

        debug_assert!(
            meminfo.mem_slots > (TARGET_EXP - MIN_EXP),
            "Not enough memory slots available"
        );

        let log_rest = msb(meminfo.mem_slots - (TARGET_EXP - MIN_EXP));
        // cap, so that max_exp >= MIN_EXP
        let max_exp = TARGET_EXP - log_rest.min(TARGET_EXP - MIN_EXP);

        // With mem_slots == 509, this gives 508 slots for ballooning
        // Starting with 2^25 = 32 MiB to 2^38 = 256 GiB takes 13 slots
        // gives 495 slots a 2^39 = 512 GiB
        // equals a maximum memory of 495 * 512 GiB - (32 MiB - 1)
        // = 247.5 TiB - 32 MiB + 1
        // which is only a little bit less than the max. 256 TiB
        // max_mem = (mem_slots - max_exp + MIN_EXP) * (1usize << max_exp)
        //    - (1usize << (MIN_EXP - 1));

        let min_alloc = 1usize << MIN_EXP;
        let max_alloc = 1usize << max_exp;

        free_mem.ent[0].start = start.raw();
        free_mem.ent[0].end = boot_info.mem_size;
        free_mem.ent[0].virt_offset = meminfo.virt_offset;

        debug_assert_ne!(free_mem.ent[0].end, 0);

        let mut allocator = FrameAllocator {
            min_alloc,
            max_alloc,
            free_mem,
            next_page: start.raise(),
            next_huge_page: start.raise(),
        };

        // Allocate enough pages to hold all memory slots in advance
        let num_pages = meminfo.mem_slots / FREE_MEM_LIST_NUM_ENTRIES;
        // There is already one FreeMemListPage present, so we can ignore the rest of the division.
        let mut last_page = &mut allocator.free_mem as *mut FreeMemListPage;

        for _ in 0..num_pages {
            let new_page = allocator.allocate_free_mem_list();
            (*last_page).header.next = Some(&mut *new_page);
            last_page = new_page;
        }

        allocator
    }

    fn allocate_free_mem_list(&mut self) -> *mut FreeMemListPage {
        let page: PhysFrame<Size4KiB> = self.allocate_frame().unwrap();
        // We know that FreeMemListPage is of size Size4KiB
        let phys_address =
            Address::<usize, _>::from(page.start_address().as_u64() as *mut FreeMemListPage);
        let shim_phys_page = ShimPhysAddr::from(phys_address);
        let shim_page = ShimVirtAddr::from(shim_phys_page);
        let page: *mut FreeMemListPage = shim_page.into();
        unsafe {
            page.write_bytes(0, 1);
        }
        page
    }

    /// Translate a shim virtual address to a host virtual address
    pub fn phys_to_host<U>(&self, val: ShimPhysUnencryptedAddr<U>) -> HostVirtAddr<U> {
        let val: u64 = val.raw().raw();
        let offset = self.get_virt_offset(val as _).unwrap();

        unsafe {
            HostVirtAddr::new(Address::<u64, U>::unchecked(
                val.checked_add(offset as u64).unwrap(),
            ))
        }
    }

    fn get_virt_offset(&self, addr: usize) -> Option<i64> {
        let mut free = &self.free_mem;
        loop {
            for i in free.ent.iter() {
                if i.start == 0 {
                    panic!(
                        "Trying to get virtual offset from unmmapped location {:#?}",
                        addr
                    );
                }
                if i.end > addr {
                    return Some(i.virt_offset);
                }
            }
            match free.header.next {
                None => return None,
                Some(ref f) => free = *f,
            }
        }
    }

    fn balloon(&mut self, addr: usize) -> Result<(), ()> {
        let mut free = &mut self.free_mem;
        let mut last_end: usize = 0;
        let mut last_size: usize = self.min_alloc;
        loop {
            for i in free.ent.iter_mut() {
                // An empty slot
                if i.start == 0 {
                    loop {
                        // request new memory from the host
                        let new_size: usize = 2u64.checked_mul(last_size as u64).unwrap() as _;
                        let new_size = new_size.min(self.max_alloc);
                        let num_pages = new_size.checked_div(Page4KiB::size() as _).unwrap();
                        if let Ok(virt_offset) = HOST_CALL.lock().balloon(num_pages) {
                            i.virt_offset = virt_offset;
                            i.start = last_end;
                            i.end = i.start.checked_add(new_size).unwrap();
                            return Ok(());
                        }

                        // Failed to get more memory.
                        // Try again with half of the memory.
                        last_size = last_size.checked_div(2).unwrap();
                        if last_size < Page4KiB::size() {
                            // Host does not have even a page of memory
                            return Err(());
                        }
                    }
                }
                if i.start > addr {
                    // should never happen
                    return Err(());
                }
                if i.end > addr {
                    // this slot has enough room
                    return Ok(());
                }
                last_end = i.end;
                last_size = i.end.checked_sub(i.start).unwrap();
                last_size = align_up(last_size as _, Page4KiB::size() as _) as _;
                last_size = last_size.max(self.min_alloc);
            }
            // we have reached the end of the free slot page
            // advance to the next page
            match free.header.next.as_deref_mut() {
                None => return Err(()),
                Some(f) => free = f,
            }
        }
    }

    #[inline(always)]
    fn do_allocate_and_map_memory<S: PageSize>(
        frame_allocator: &mut (impl paging::FrameAllocator<S> + paging::FrameAllocator<Size4KiB>),
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
        FrameAllocator::do_allocate_and_map_memory(self, &pre, mapper, flags, parent_flags)?;
        FrameAllocator::do_allocate_and_map_memory(self, &middle, mapper, flags, parent_flags)?;
        FrameAllocator::do_allocate_and_map_memory(self, &post, mapper, flags, parent_flags)?;

        // transmute the whole thing to one big bytes slice
        Ok(unsafe { core::slice::from_raw_parts_mut(pre.as_mut_ptr() as *mut u8, size) })
    }

    /// Map physical memory to the given virtual address
    ///
    /// FIXME: change PhysAddr to ShimPhysAddr to ensure encrypted memory
    pub fn map_memory<T: Mapper<Size4KiB> + Mapper<Size2MiB>>(
        &mut self,
        mapper: &mut T,
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

unsafe impl paging::FrameAllocator<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame_address = self.next_page;
        self.next_page += Offset::from_items(1);

        // if at the start of a 2MiB page, advance to the next free 2MiB
        if self.next_page.raw() == self.next_page.raise::<Page2MiB>().raw() {
            self.next_page = self.next_huge_page.raise();
        }

        if frame_address.raw() >= self.next_huge_page.raw() {
            // we have taken a bite out of the next 2MiB page
            // so advance the 2MiB pointer
            self.next_huge_page += Offset::from_items(1);

            if self.balloon(self.next_huge_page.raw()).is_err() {
                // OOM
                return None;
            }
        }

        if self.balloon(self.next_page.raw()).is_err() {
            // OOM
            return None;
        }

        Some(PhysFrame::containing_address(PhysAddr::new(
            frame_address.raw() as u64 | get_cbit_mask(),
        )))
    }
}

unsafe impl paging::FrameAllocator<Size2MiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let frame_address = self.next_huge_page;
        self.next_huge_page += Offset::from_items(1);

        if self.balloon(self.next_huge_page.raw()).is_err() {
            // OOM
            return None;
        }

        Some(PhysFrame::containing_address(PhysAddr::new(
            frame_address.raw() as u64 | get_cbit_mask(),
        )))
    }
}
