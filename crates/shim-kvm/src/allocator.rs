// SPDX-License-Identifier: Apache-2.0

//! The global Allocator

use crate::addr::{ShimPhysAddr, ShimVirtAddr, SHIM_VIRT_OFFSET};
use crate::exec::NEXT_MMAP_RWLOCK;
use crate::hostcall::{HostCall, SHIM_LOCAL_STORAGE};
use crate::paging::{EncPhysOffset, SHIM_PAGETABLE};
use crate::snp::{get_cbit_mask, pvalidate, snp_active, PvalidateSize};

use core::alloc::{GlobalAlloc, Layout};
use core::cmp::{max, min};
use core::convert::TryFrom;
use core::mem::{align_of, size_of};
use core::ops::Deref;
use core::ptr::NonNull;

use goblin::elf::header::header64::Header;
use goblin::elf::header::ELFMAG;
use goblin::elf::program_header::program_header64::*;
use linked_list_allocator::Heap;
use lset::{Line, Span};
use primordial::{Address, Page as Page4KiB};
use sallyport::guest::Handler;
use spin::{Lazy, Mutex, RwLockWriteGuard};
use x86_64::instructions::tlb::flush_all;
use x86_64::structures::paging::mapper::{MapToError, UnmapError};
use x86_64::structures::paging::{
    self, FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size1GiB, Size2MiB, Size4KiB,
};
use x86_64::structures::paging::{MappedPageTable, PageSize};
use x86_64::{align_down, align_up, PhysAddr, VirtAddr};

/// Frame of the zero page
pub static ZERO_PAGE_FRAME: Lazy<PhysFrame<Size4KiB>> = Lazy::new(|| {
    let frame = ALLOCATOR.lock().allocate_frame().unwrap();
    let shim_phys_page = ShimPhysAddr::try_from(frame.start_address()).unwrap();
    let shim_virt: *mut u8 = ShimVirtAddr::from(shim_phys_page).into();
    unsafe {
        core::ptr::write_bytes(shim_virt, 0, Size4KiB::SIZE as _);
    }
    frame
});

/// A global allocator that uses the `EnarxAllocator` to allocate memory.
pub struct LockedEnarxAllocator {
    inner: Lazy<Mutex<EnarxAllocator>>,
}

impl Deref for LockedEnarxAllocator {
    type Target = Lazy<Mutex<EnarxAllocator>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// The global EnarxAllocator
#[cfg_attr(target_os = "none", global_allocator)]
pub static ALLOCATOR: LockedEnarxAllocator = LockedEnarxAllocator {
    inner: Lazy::new(|| Mutex::new(unsafe { EnarxAllocator::new() })),
};

/// The allocator
///
/// The allocator struct is holding a linked list Heap allocator
/// and information about the hypervisor's capabilities to
/// extend the available memory.
///
/// It also implements:
/// * paging::FrameAllocator<Size4KiB>
/// * paging::FrameAllocator<Size2MiB>
pub struct EnarxAllocator {
    last_alloc: usize,
    max_alloc: usize,
    end_of_mem: PhysAddr,
    allocator: Heap,
}

impl core::fmt::Debug for EnarxAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("EnarxAllocator")
            .field("last_alloc", &self.last_alloc)
            .field("max_alloc", &self.max_alloc)
            .finish()
    }
}

/// Get the most significant bit set
/// Poor man's log2
#[inline]
#[allow(clippy::integer_arithmetic)]
fn msb(val: usize) -> u32 {
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

/// Error returned by the `EnarxAllocator`
#[derive(Debug)]
pub enum AllocateError {
    /// Memory or Size not page aligned
    NotAligned,
    /// Out of Memory
    OutOfMemory,
    /// Requested memory size of zero
    ZeroSize,
    /// Error mapping the page
    PageAlreadyMapped,
    /// An upper level page table entry has the `HUGE_PAGE` flag set, which means that the
    /// given page is part of an already mapped huge page.
    ParentEntryHugePage,
}

impl EnarxAllocator {
    unsafe fn new() -> Self {
        let mut tls = SHIM_LOCAL_STORAGE.write();
        let meminfo = {
            let mut host_call = HostCall::try_new(&mut tls).unwrap();
            host_call.mem_info().unwrap()
        };
        drop(tls);

        const MIN_EXP: u32 = 24; // start with 2^24 = 16 MiB
        let c_bit_mask = get_cbit_mask();
        let target_exp: u32 = if c_bit_mask > 0 {
            u32::min(47, msb(c_bit_mask as _).checked_sub(1).unwrap()) // don't want to address more than c_bit_mask
        } else {
            47 // we want more than 2^47 = 128 TiB
        };

        debug_assert!(
            meminfo > (target_exp.checked_sub(MIN_EXP).unwrap()) as _,
            "Not enough memory slots available"
        );

        let log_rest = msb(meminfo
            .checked_sub(target_exp.checked_sub(MIN_EXP).unwrap() as usize)
            .unwrap());
        // cap, so that max_exp >= MIN_EXP
        let max_exp = target_exp
            .checked_sub(log_rest.min(target_exp.checked_sub(MIN_EXP).unwrap()))
            .unwrap();

        // With mem_slots == 509, this gives 508 slots for ballooning
        // Starting with 2^25 = 32 MiB to 2^38 = 256 GiB takes 13 slots
        // gives 495 slots a 2^39 = 512 GiB
        // equals a maximum memory of 495 * 512 GiB - (32 MiB - 1)
        // = 247.5 TiB - 32 MiB + 1
        // which is only a little bit less than the max. 256 TiB
        // max_mem = (mem_slots - max_exp + MIN_EXP) * (1usize << max_exp)
        //    - (1usize << (MIN_EXP - 1));

        let next_alloc = (2usize).checked_pow(MIN_EXP).unwrap();
        let max_alloc = (2usize).checked_pow(max_exp).unwrap();

        let mem_start: PhysAddr = {
            let shim_virt = ShimVirtAddr::from(&crate::_ENARX_MEM_START);
            PhysAddr::new(ShimPhysAddr::try_from(shim_virt).unwrap().raw().raw())
        };

        let code_size = {
            let header: &Header = &crate::_ENARX_EXEC_START;
            let header_ptr = header as *const _;

            if !header.e_ident[..ELFMAG.len()].eq(ELFMAG) {
                panic!("Not valid ELF");
            }

            let headers: &[ProgramHeader] = core::slice::from_raw_parts(
                (header_ptr as usize as *const u8).offset(header.e_phoff as _)
                    as *const ProgramHeader,
                header.e_phnum as _,
            );

            let region = Span::from(
                headers
                    .iter()
                    .filter(|ph| ph.p_type == PT_LOAD)
                    .map(|x| {
                        Line::from(
                            x.p_vaddr as usize
                                ..(x.p_vaddr as usize)
                                    .checked_add(x.p_memsz as usize)
                                    .unwrap(),
                        )
                    })
                    .fold(
                        Line {
                            start: usize::MAX,
                            end: usize::MIN,
                        },
                        |l, r| Line::from(min(l.start, r.start)..max(l.end, r.end)),
                    ),
            );

            assert!(
                (&crate::_ENARX_EXEC_END as *const _ as usize)
                    .checked_sub(&crate::_ENARX_EXEC_START as *const _ as usize)
                    .unwrap()
                    > region.count
            );

            align_up(region.count as u64, Page4KiB::SIZE as u64) as usize
        };

        let mem_size = align_up(
            (&crate::_ENARX_EXEC_START as *const _ as u64)
                .checked_sub(&crate::_ENARX_MEM_START as *const _ as u64)
                .unwrap()
                .checked_add(code_size as u64)
                .unwrap(),
            Page4KiB::SIZE as u64,
        ) as usize;

        let end_of_mem = mem_start + mem_size;

        let mut nmr = NEXT_MMAP_RWLOCK.write();
        *nmr = (*nmr + code_size).align_up(Page::<Size4KiB>::SIZE);

        let allocator = Heap::empty();

        EnarxAllocator {
            last_alloc: next_alloc.checked_div(2).unwrap(),
            max_alloc,
            end_of_mem,
            allocator,
        }
    }

    fn balloon(&mut self) -> bool {
        let mut last_size: usize = self.last_alloc;

        loop {
            // request new memory from the host
            let new_size: usize = 2u64
                .checked_mul(last_size as u64)
                .unwrap_or(last_size as u64) as _;
            let new_size = new_size.min(self.max_alloc);
            let num_pages = new_size.checked_div(Page4KiB::SIZE as _).unwrap();

            let mut tls = SHIM_LOCAL_STORAGE.write();
            let ret = HostCall::try_new(&mut tls).unwrap().balloon_memory(
                12, // 1 << 12 == 4096 == page size
                num_pages,
                self.end_of_mem.as_u64() as _,
            );
            drop(tls);

            match ret {
                Ok(_) => {
                    // convert to shim virtual address
                    let shim_phys_page = ShimPhysAddr::<u8>::try_from(self.end_of_mem).unwrap();
                    let free_start: *mut u8 = ShimVirtAddr::from(shim_phys_page).into();

                    // increase end of memory
                    self.end_of_mem += new_size;

                    if snp_active() {
                        // pvalidate the newly assigned memory region
                        let virt_region = Span::new(free_start as usize, new_size);
                        let virt_line = Line::from(virt_region);

                        for addr in
                            (virt_line.start..virt_line.end).step_by(Page::<Size4KiB>::SIZE as _)
                        {
                            let va = VirtAddr::new(addr as _);
                            pvalidate(va, PvalidateSize::Size4K, true).unwrap();
                        }
                    }

                    unsafe {
                        if self.allocator.size() > 0 {
                            self.allocator.extend(new_size);
                        } else {
                            self.allocator.init(free_start as _, new_size);
                        }
                    }
                    self.last_alloc = new_size;

                    return true;
                }
                Err(_) => {
                    // Failed to get more memory.
                    // Try again with half of the memory.
                    last_size = last_size.checked_div(2).unwrap();
                    if last_size < Page4KiB::SIZE {
                        // Host does not have even a page of memory
                        return false;
                    }
                }
            }
        }
    }

    fn try_alloc_half(&mut self, mut size: usize) -> (*mut u8, usize) {
        assert!(size >= size_of::<Page4KiB>());
        loop {
            let p = self.alloc_pages(size);

            if let Ok(p) = p {
                unsafe {
                    core::ptr::write_bytes(p.as_ptr(), 0, size);
                }
                return (p.as_ptr(), size);
            }

            if size == size_of::<Page4KiB>() {
                return (core::ptr::null_mut(), size);
            }

            size = size.checked_div(2).unwrap();
        }
    }

    fn alloc_pages(&mut self, size: usize) -> Result<NonNull<u8>, ()> {
        self.allocator
            .allocate_first_fit(Layout::from_size_align(size, align_of::<Page4KiB>()).unwrap())
    }

    unsafe fn dealloc_pages(&mut self, ptr: *mut u8, size: usize) {
        self.allocator.deallocate(
            NonNull::new_unchecked(ptr),
            Layout::from_size_align_unchecked(size, align_of::<Page4KiB>()),
        )
    }

    /// Allocate memory and map it to the given virtual address
    pub fn allocate_and_map_memory(
        &mut self,
        map_to: VirtAddr,
        size: usize,
        flags: PageTableFlags,
        parent_flags: PageTableFlags,
    ) -> Result<&'static mut [u8], AllocateError> {
        if size == 0 {
            return Err(AllocateError::ZeroSize);
        }

        if !map_to.is_aligned(align_of::<Page4KiB>() as u64) {
            return Err(AllocateError::NotAligned);
        }

        if size != align_down(size as _, Page::<Size4KiB>::SIZE) as usize {
            return Err(AllocateError::NotAligned);
        }

        let curr_size = (2usize).checked_pow(msb(size)).unwrap();

        let (first_half, first_half_size) = {
            while self.allocator.free() < curr_size {
                self.balloon();
            }
            let (chunk, chunk_size) = self.try_alloc_half(curr_size);

            if chunk.is_null() {
                self.balloon();
                self.try_alloc_half(curr_size)
            } else {
                (chunk, chunk_size)
            }
        };

        if first_half.is_null() {
            return Err(AllocateError::OutOfMemory);
        }

        let second_half_size = size.checked_sub(first_half_size).unwrap();

        if second_half_size > 0 {
            if let Err(e) = self.allocate_and_map_memory(
                map_to + first_half_size,
                second_half_size,
                flags,
                parent_flags,
            ) {
                unsafe {
                    self.dealloc_pages(first_half, first_half_size);
                }
                return Err(e);
            }
        }

        let phys = shim_virt_to_enc_phys(first_half);
        if let Err(e) = self.map_memory(phys, map_to, first_half_size, flags, parent_flags) {
            unsafe {
                self.dealloc_pages(first_half, first_half_size);
            }
            let _ = self.unmap_memory(map_to + first_half_size, second_half_size);
            return Err(e);
        }
        // transmute the whole thing to one big bytes slice
        Ok(unsafe { core::slice::from_raw_parts_mut(map_to.as_mut_ptr() as *mut u8, size) })
    }

    /// Map the zero page to the given virtual address
    ///
    /// FIXME: change PhysAddr to ShimPhysAddr to ensure encrypted memory
    pub fn map_memory_zero(
        &mut self,
        shim_page_table: &mut RwLockWriteGuard<'_, MappedPageTable<'_, EncPhysOffset>>,
        map_to: VirtAddr,
        size: usize,
        mut flags: PageTableFlags,
        parent_flags: PageTableFlags,
    ) -> Result<&'static mut [u8], AllocateError> {
        if size == 0 {
            return Err(AllocateError::ZeroSize);
        }

        let page_range_to = {
            let start = map_to;
            let end = start + size - 1u64;
            let start_page = Page::<Size4KiB>::containing_address(start);
            let end_page = Page::<Size4KiB>::containing_address(end);
            Page::range_inclusive(start_page, end_page)
        };

        if flags.contains(PageTableFlags::WRITABLE) {
            flags.remove(PageTableFlags::WRITABLE);
            flags |= PageTableFlags::BIT_10;
        }

        let zero_frame = *ZERO_PAGE_FRAME;

        for page_to in page_range_to {
            unsafe {
                shim_page_table
                    .map_to_with_table_flags(page_to, zero_frame, flags, parent_flags, self)
                    .map_err(|e| match e {
                        MapToError::FrameAllocationFailed => AllocateError::OutOfMemory,
                        MapToError::ParentEntryHugePage => AllocateError::ParentEntryHugePage,
                        MapToError::PageAlreadyMapped(_) => AllocateError::PageAlreadyMapped,
                    })?
                    .ignore();
            }
        }
        flush_all();

        // transmute the whole thing to one big bytes slice
        Ok(unsafe { core::slice::from_raw_parts_mut(map_to.as_mut_ptr() as *mut u8, size) })
    }

    /// Map physical memory to the given virtual address
    ///
    /// FIXME: change PhysAddr to ShimPhysAddr to ensure encrypted memory
    pub fn map_memory(
        &mut self,
        map_from: PhysAddr,
        map_to: VirtAddr,
        size: usize,
        flags: PageTableFlags,
        parent_flags: PageTableFlags,
    ) -> Result<(), AllocateError> {
        if size == 0 {
            return Err(AllocateError::ZeroSize);
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

        let mut shim_page_table = SHIM_PAGETABLE.write();

        for (frame_from, page_to) in frame_range_from.zip(page_range_to) {
            unsafe {
                shim_page_table
                    .map_to_with_table_flags(page_to, frame_from, flags, parent_flags, self)
                    .map_err(|e| match e {
                        MapToError::FrameAllocationFailed => AllocateError::OutOfMemory,
                        MapToError::ParentEntryHugePage => AllocateError::ParentEntryHugePage,
                        MapToError::PageAlreadyMapped(_) => AllocateError::PageAlreadyMapped,
                    })?
                    .ignore();
            }
        }
        flush_all();

        Ok(())
    }

    /// FIXME: unmap
    pub fn unmap_memory(&mut self, virt_addr: VirtAddr, size: usize) -> Result<(), UnmapError> {
        if size == 0 {
            return Ok(());
        }

        let page_range_to = {
            let start = virt_addr;
            let end = start + size - 1u64;
            let start_page = Page::<Size4KiB>::containing_address(start);
            let end_page = Page::<Size4KiB>::containing_address(end);
            Page::range_inclusive(start_page, end_page)
        };

        for frame_from in page_range_to {
            let (phys_frame, _) = SHIM_PAGETABLE.write().unmap(frame_from)?;
            if phys_frame == *ZERO_PAGE_FRAME {
                continue;
            }

            let phys = phys_frame.start_address();

            let free_start_phys = Address::<usize, _>::from(phys.as_u64() as *const u8);
            let shim_phys_page = ShimPhysAddr::from(free_start_phys);
            let shim_virt: *mut u8 = ShimVirtAddr::from(shim_phys_page).into();
            unsafe {
                self.dealloc_pages(shim_virt, Page::<Size4KiB>::SIZE as usize);
            }
        }

        flush_all();
        Ok(())
    }

    /// Allocate memory by Layout
    pub fn try_alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let b = self.allocator.allocate_first_fit(layout).ok();

        if b.is_none() && self.balloon() {
            // try once again to allocate
            self.allocator.allocate_first_fit(layout).ok()
        } else {
            b
        }
    }

    /// Deallocate memory
    ///
    /// # Safety
    ///
    /// Unsafe, because the caller has to ensure to not use any references left.
    pub unsafe fn deallocate(&mut self, ptr: *mut u8, layout: Layout) {
        self.allocator
            .deallocate(NonNull::new(ptr).unwrap(), layout);
    }

    /// returns the amount of free memory
    pub fn free(&self) -> usize {
        self.allocator.free()
    }
}

unsafe impl paging::FrameAllocator<Size4KiB> for EnarxAllocator {
    #[allow(unused_unsafe)]
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.try_alloc(unsafe {
            Layout::from_size_align_unchecked(
                Page::<Size4KiB>::SIZE as _,
                Page::<Size4KiB>::SIZE as _,
            )
        })
        .map(|a| a.as_ptr())
        .map(shim_virt_to_enc_phys)
        .map(PhysFrame::containing_address)
    }
}

unsafe impl paging::FrameAllocator<Size2MiB> for EnarxAllocator {
    #[allow(unused_unsafe)]
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        self.try_alloc(unsafe {
            Layout::from_size_align_unchecked(
                Page::<Size2MiB>::SIZE as _,
                Page::<Size2MiB>::SIZE as _,
            )
        })
        .map(|a| a.as_ptr())
        .map(shim_virt_to_enc_phys)
        .map(PhysFrame::containing_address)
    }
}

unsafe impl paging::FrameAllocator<Size1GiB> for EnarxAllocator {
    #[allow(unused_unsafe)]
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        self.try_alloc(unsafe {
            Layout::from_size_align_unchecked(
                Page::<Size1GiB>::SIZE as _,
                Page::<Size1GiB>::SIZE as _,
            )
        })
        .map(|a| a.as_ptr())
        .map(shim_virt_to_enc_phys)
        .map(PhysFrame::containing_address)
    }
}

// We can't use `ShimPhysAddr::try_from` because `SHIM_PAGETABLE` can't be locked
// but we need it to point to encrypted pages anyway.
#[inline]
fn shim_virt_to_enc_phys<T>(p: *mut T) -> PhysAddr {
    let virt = VirtAddr::from_ptr(p);
    debug_assert!(virt.as_u64() > SHIM_VIRT_OFFSET);
    PhysAddr::new(virt.as_u64().checked_sub(SHIM_VIRT_OFFSET).unwrap() | get_cbit_mask())
}

unsafe impl GlobalAlloc for LockedEnarxAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut this = self.inner.lock();
        this.try_alloc(layout)
            .map_or(core::ptr::null_mut(), |p| p.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut this = self.inner.lock();
        this.deallocate(ptr, layout);
    }
}
