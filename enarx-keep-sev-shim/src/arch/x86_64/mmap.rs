// SPDX-License-Identifier: Apache-2.0

use crate::arch::x86_64::structures::paging::{
    mapper::MapToError, FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
};

//FIXME: use x86_64::structures::paging::FrameDeallocator;
use x86_64::VirtAddr;

use super::FRAME_ALLOCATOR;
use super::MAPPER;
use super::NEXT_MMAP;
use super::PAGESIZE;

// TODO: multi-thread or syscall-proxy
pub fn mmap_user(len: usize) -> *mut u8 {
    let virt_start_addr;
    unsafe {
        virt_start_addr = VirtAddr::new(NEXT_MMAP as u64);
    }
    let start_page: Page = Page::containing_address(virt_start_addr);
    let end_page: Page = Page::containing_address(virt_start_addr + len - 1u64);
    let page_range = Page::range_inclusive(start_page, end_page);

    let mut frame_allocator;
    let mut mapper;
    unsafe {
        frame_allocator = FRAME_ALLOCATOR.take().unwrap();
        mapper = MAPPER.take().unwrap();
    }
    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::<Size4KiB>::FrameAllocationFailed)
            .unwrap();

        //println!("page {:#?} frame {:#?}", page, frame);

        mapper
            .map_to(
                page,
                frame,
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE,
                PageTableFlags::USER_ACCESSIBLE,
                &mut frame_allocator,
            )
            .and_then(|f| {
                f.flush();
                Ok(())
            })
            .or_else(|e| match e {
                MapToError::PageAlreadyMapped(_f) => {
                    //FIXME: frame_allocator.deallocate_frame(f);
                    Ok(())
                }
                MapToError::ParentEntryHugePage => Ok(()),
                _ => Err(e),
            })
            .unwrap();
    }

    let ret;
    unsafe {
        ret = NEXT_MMAP as *mut u8;
        ret.write_bytes(0u8, len);

        NEXT_MMAP = (virt_start_addr + len).align_up(PAGESIZE as u64).as_u64();

        FRAME_ALLOCATOR.replace(frame_allocator);
        MAPPER.replace(mapper);
    }
    ret
}

// TODO: muti-thread or syscall-proxy
pub fn brk_user(len: usize) -> *mut u8 {
    let virt_start_addr;
    unsafe {
        virt_start_addr = VirtAddr::new(NEXT_MMAP as u64);
    }
    let start_page: Page = Page::containing_address(virt_start_addr);
    let end_page: Page = Page::containing_address(virt_start_addr + len - 1u64);
    let page_range = Page::range_inclusive(start_page, end_page);

    let mut frame_allocator;
    let mut mapper;
    unsafe {
        frame_allocator = FRAME_ALLOCATOR.take().unwrap();
        mapper = MAPPER.take().unwrap();
    }

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::<Size4KiB>::FrameAllocationFailed)
            .unwrap();
        //println!("page {:#?} frame {:#?}", page, frame);
        mapper
            .map_to(
                page,
                frame,
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE,
                PageTableFlags::USER_ACCESSIBLE,
                &mut frame_allocator,
            )
            .and_then(|f| {
                f.flush();
                Ok(())
            })
            .or_else(|e| match e {
                MapToError::PageAlreadyMapped(_f) => {
                    //FIXME: frame_allocator.deallocate_frame(f);
                    Ok(())
                }
                MapToError::ParentEntryHugePage => Ok(()),
                _ => Err(e),
            })
            .unwrap();
    }

    let ret;
    unsafe {
        ret = NEXT_MMAP as *mut u8;
        NEXT_MMAP += len as u64;
        ret.write_bytes(0u8, len);

        FRAME_ALLOCATOR.replace(frame_allocator);
        MAPPER.replace(mapper);
    }
    ret
}
