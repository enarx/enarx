// SPDX-License-Identifier: Apache-2.0

use super::gdt;
use super::interrupts;
use super::syscall;
use super::xcr0::{XCr0, XCr0Flags};
use crate::memory::BootInfoFrameAllocator;
use vmsyscall::bootinfo::BootInfo;
use vmsyscall::memory_map::MemoryRegionType;

use crate::arch::x86_64::structures::paging::{
    mapper::MapToError, FrameAllocator, Mapper, OffsetPageTable, Page, PageTableFlags, Size4KiB,
};

pub use x86_64::{PhysAddr, VirtAddr};

use super::APP_ENTRY_POINT;
use super::APP_LOAD_ADDR;
use super::APP_PH_NUM;
use super::FRAME_ALLOCATOR;
use super::MAPPER;
use super::NEXT_MMAP;
use super::STACK_SIZE;
use super::STACK_START;
use crate::arch::x86_64::PAGESIZE;

const PHYSICAL_MEMORY_OFFSET: u64 = 0x800_0000_0000;

#[allow(clippy::type_complexity)]
static mut ENTRY_POINT: Option<
    fn(
        mapper: &mut OffsetPageTable,
        frame_allocator: &mut BootInfoFrameAllocator,
        app_entry_point: *const u8,
        app_load_addr: *const u8,
        app_phnum: usize,
    ) -> !,
> = None;

pub fn init(
    boot_info: &'static mut BootInfo,
    entry_point: fn(
        mapper: &mut OffsetPageTable,
        frame_allocator: &mut BootInfoFrameAllocator,
        app_entry_point: *const u8,
        app_load_addr: *const u8,
        app_phnum: usize,
    ) -> !,
) -> ! {
    crate::arch::init_syscall(boot_info);
    let boot_info = boot_info.clone();

    // *********************************
    // NO println! before this point!!
    // *********************************

    unsafe {
        let xsave_supported = (core::arch::x86_64::__cpuid(1).ecx & (1 << 26)) != 0;
        assert!(xsave_supported);

        let xsaveopt_supported = (core::arch::x86_64::__cpuid_count(0xD, 1).eax & 1) == 1;
        assert!(xsaveopt_supported);

        let sse_extended_supported =
            (core::arch::x86_64::__cpuid_count(0xd, 0).eax & 0b111) == 0b111;
        if sse_extended_supported {
            XCr0::update(|xcr0| xcr0.insert(XCr0Flags::YMM));
        } else {
            XCr0::update(|xcr0| xcr0.insert(XCr0Flags::SSE));
        }

        let xsave_size = core::arch::x86_64::__cpuid(0xD).ebx;
        assert!(xsave_size < (16 * 64 - 64));
    }
    gdt::init();
    unsafe { syscall::init() };

    //    #[cfg(feature = "nightly")]
    interrupts::init();

    eprintln!("{:#?}", boot_info);

    let phys_mem_offset = VirtAddr::new(PHYSICAL_MEMORY_OFFSET);

    unsafe { MAPPER.replace(crate::memory::init(phys_mem_offset)) };

    unsafe {
        APP_ENTRY_POINT = boot_info.entry_point;
        APP_LOAD_ADDR = boot_info.load_addr;
        APP_PH_NUM = boot_info.elf_phnum;
    }

    unsafe {
        let e = boot_info
            .memory_map
            .iter()
            .filter(|e| e.region_type == MemoryRegionType::Usable)
            .last()
            .unwrap();
        assert!(e.region_type == MemoryRegionType::Usable);
        NEXT_MMAP = e.range.start_addr();
        eprintln!("NEXT_MMAP = {:#X}", NEXT_MMAP);
    }

    let mut frame_allocator = unsafe { BootInfoFrameAllocator::init(boot_info.memory_map) };

    #[cfg(feature = "allocator")]
    init_heap(unsafe { MAPPER.as_mut().unwrap() }, &mut frame_allocator)
        .expect("heap initialization failed");

    let stack_pointer = init_stack(unsafe { MAPPER.as_mut().unwrap() }, &mut frame_allocator)
        .expect("stack initialization failed");

    unsafe {
        FRAME_ALLOCATOR.replace(frame_allocator);
        ENTRY_POINT.replace(entry_point);
    }

    unsafe { crate::_context_switch(init_after_stack_swap, stack_pointer.as_u64() as _) }
}

#[cfg(feature = "allocator")]
pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    use super::HEAP_SIZE;
    use super::HEAP_START;

    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    eprintln!("Trying to allocate heap: {:#?}", page_range);

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

        mapper
            .map_to(page, frame, flags, PageTableFlags::empty(), frame_allocator)?
            .flush();
    }
    eprintln!("Heap alloc done");

    unsafe {
        crate::ALLOCATOR.lock().init(HEAP_START, HEAP_SIZE);
    }

    Ok(())
}

pub fn init_stack(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let stack_start = VirtAddr::new(STACK_START as u64);
    let stack_end = stack_start + STACK_SIZE - 1u64;
    let stack_start_page = Page::containing_address(stack_start);
    let stack_end_page = Page::containing_address(stack_end);

    let page_range = { Page::range_inclusive(stack_start_page + 1, stack_end_page - 1) };

    eprintln!("Trying to allocate stack: {:#?}", page_range);

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        mapper
            .map_to(page, frame, flags, PageTableFlags::empty(), frame_allocator)?
            .flush();
    }

    // Guard Pages
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    let flags = PageTableFlags::PRESENT;
    mapper
        .map_to(
            stack_start_page,
            frame,
            flags,
            PageTableFlags::empty(),
            frame_allocator,
        )?
        .flush();

    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    let flags = PageTableFlags::PRESENT;
    mapper
        .map_to(
            stack_end_page,
            frame,
            flags,
            PageTableFlags::empty(),
            frame_allocator,
        )?
        .flush();

    use core::ops::Sub;

    let stack_pointer = stack_end.sub(PAGESIZE).align_down(64u64);

    unsafe {
        gdt::TSS.as_mut().unwrap().privilege_stack_table[0] = stack_pointer;
    }

    Ok(stack_pointer)
}

extern "C" fn init_after_stack_swap() -> ! {
    let frame_allocator = unsafe { FRAME_ALLOCATOR.as_mut().unwrap() };
    let mapper = unsafe { MAPPER.as_mut().unwrap() };
    let entry_point = unsafe { ENTRY_POINT.as_ref().unwrap() };

    unsafe {
        entry_point(
            mapper,
            frame_allocator,
            APP_ENTRY_POINT,
            APP_LOAD_ADDR,
            APP_PH_NUM,
        )
    }
}
