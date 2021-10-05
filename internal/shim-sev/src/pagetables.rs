// SPDX-License-Identifier: Apache-2.0

//! Initial Page Tables
//!
//! * PDT_IDENT: an identity mapped one for 0x0 - 0x60_0000
//! * PDPT_OFFSET: an offset page table with offset $SHIM_OFFSET

use crate::addr::SHIM_VIRT_OFFSET;
use crate::addr::{BYTES_1_GIB, BYTES_2_MIB};
use crate::debug::_early_debug_panic;
use crate::paging::EncPhysOffset;
use crate::{
    paging, _ENARX_EXEC_END, _ENARX_SALLYPORT_END, _ENARX_SALLYPORT_START, _ENARX_SHIM_START,
};
use array_const_fn_init::array_const_fn_init;
use x86_64::instructions::tlb::flush;
use x86_64::structures::paging::mapper::{MappedFrame, PageTableFrameMapping, TranslateResult};
use x86_64::structures::paging::{
    Mapper, Page, PageTable, PageTableFlags, Size1GiB, Size2MiB, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

/// A page-aligned Page Table.
#[repr(C, align(4096))]
pub struct AlignedPageTable(pub [u64; 512]);

const HUGE_PAGE_TABLE_FLAGS: u64 = PageTableFlags::HUGE_PAGE.bits()
    | PageTableFlags::WRITABLE.bits()
    | PageTableFlags::PRESENT.bits();

#[allow(clippy::integer_arithmetic)]
const fn gen_2mb_pdt_entries(i: usize, offset: u64) -> u64 {
    let base: u64 = HUGE_PAGE_TABLE_FLAGS + offset;
    let step: u64 = BYTES_2_MIB;
    base + (i as u64) * step
}

#[allow(clippy::integer_arithmetic)]
const fn gen_2mb_pdt_entries_c000_0000(i: usize) -> u64 {
    gen_2mb_pdt_entries(i, 0xc000_0000)
}

#[allow(clippy::integer_arithmetic)]
const fn gen_1gb_pdpt_entries(i: usize) -> u64 {
    let base: u64 = HUGE_PAGE_TABLE_FLAGS;
    let step: u64 = BYTES_1_GIB;
    base + (i as u64) * step
}

#[allow(clippy::integer_arithmetic)]
const fn gen_4k_pt_entries(i: usize, offset: u64) -> u64 {
    let base: u64 = (PageTableFlags::WRITABLE.bits() | PageTableFlags::PRESENT.bits()) + offset;
    let step: u64 = Page::<Size4KiB>::SIZE;
    base + (i as u64) * step
}

#[allow(clippy::integer_arithmetic)]
const fn gen_4k_pt_entries_ffe0_0000(i: usize) -> u64 {
    gen_4k_pt_entries(i, 0xffe0_0000)
}

/// The root table of the 4-Level Paging
///
/// Intel Vol 3A - 4.5
/// will contain:
///       [0] PDPT_IDENT:  0x0                   - 0x80_0000_0000
/// [1..=510] empty for now
///     [511] PDPT_OFFSET: 0xFFFF_FF80_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF
#[no_mangle]
#[link_section = ".entry64_data"]
pub static mut PML4T: AlignedPageTable = AlignedPageTable([0; 512]);

/// Offset Page-Directory-Pointer Table
///
/// with pointers to Huge Pages, mapping 38bit of addresses to
/// SHIM_OFFSET + x, making the translation of shim virtual address space
/// to physical address space easy, by substracting SHIM_OFFSET.
/// This also enables mapping user space below SHIM_OFFSET and use the same
/// CR3 for shim and user space.
#[no_mangle]
#[link_section = ".entry64_data"]
pub static mut PDPT_OFFSET: AlignedPageTable =
    AlignedPageTable(array_const_fn_init![gen_1gb_pdpt_entries; 512]);

/// Offset Page-Directory Table
#[no_mangle]
#[link_section = ".entry64_data"]
pub static mut PDT_OFFSET: AlignedPageTable =
    AlignedPageTable(array_const_fn_init![gen_2mb_pdt_entries_c000_0000; 512]);

/// Identity Page-Directory-Pointer Table
///
/// will contain a pointer to a Identity Page-Directory Table
#[no_mangle]
#[link_section = ".entry64_data"]
pub static mut PDPT_IDENT: AlignedPageTable = AlignedPageTable([0; 512]);

/// Identity Page-Directory Table
///
/// with a pointer to a 2MB Huge Page
#[no_mangle]
#[link_section = ".entry64_data"]
pub static mut PDT_IDENT: AlignedPageTable =
    AlignedPageTable(array_const_fn_init![gen_2mb_pdt_entries_c000_0000; 512]);

/// Identity Page Table
///
/// with pointers to 4KiB Huge Page
#[no_mangle]
#[link_section = ".entry64_data"]
pub static mut PT_IDENT: AlignedPageTable =
    AlignedPageTable(array_const_fn_init![gen_4k_pt_entries_ffe0_0000; 512]);

/// Map the sallyport Block pages to unencrypted memory.
pub fn switch_sallyport_to_unencrypted(c_bit_mask: u64) {
    // Unmap some pages, because a TEE is not supposed to map the same physical memory
    // encrypted and unencrypted.

    let start = VirtAddr::from_ptr(unsafe { &_ENARX_SHIM_START }) - SHIM_VIRT_OFFSET;
    let end = VirtAddr::from_ptr(unsafe { &_ENARX_EXEC_END }) - SHIM_VIRT_OFFSET;

    if unmap_address_range(start, end).is_err() {
        unsafe {
            _early_debug_panic(0xAFFE_AFFE_AFFE_AFFE, 0);
        }
    }

    let start = VirtAddr::from_ptr(unsafe { &_ENARX_SALLYPORT_START }) - SHIM_VIRT_OFFSET;
    let end = VirtAddr::from_ptr(unsafe { &_ENARX_SALLYPORT_END }) - SHIM_VIRT_OFFSET;

    if clear_c_bit_address_range(start, end, c_bit_mask).is_err() {
        unsafe {
            _early_debug_panic(0xAFFE_AFFE_AFFE_CAFE, 0);
        }
    }
}

fn unmap_address_range(start: VirtAddr, end: VirtAddr) -> Result<(), ()> {
    let mut page_table = paging::SHIM_PAGETABLE.write();
    let mut current = start;
    loop {
        if current >= end {
            return Ok(());
        }
        let trans = page_table.translate(current);
        current += match trans {
            TranslateResult::Mapped {
                frame,
                flags: _,
                offset,
            } => match frame {
                MappedFrame::Size4KiB(frame) => {
                    if offset != 0 {
                        unsafe {
                            _early_debug_panic(0xAFFE_0001_0000_0000, current.as_u64());
                        }
                        //return Err(());
                    }

                    /* FIXME: currently ok
                    if current + frame.size() > end {
                        unsafe {
                            _early_debug_panic(0xAFFE_0002_0000_0000, current.as_u64());
                        }
                        //return Err(());
                    }
                    */

                    match page_table.unmap(Page::<Size4KiB>::containing_address(current)) {
                        Ok((_frame, flush)) => flush.flush(),
                        Err(_) => {
                            unsafe {
                                _early_debug_panic(0xAFFE_0003_0000_0000, current.as_u64());
                            }
                            //return Err(());
                        }
                    }
                    frame.size()
                }
                MappedFrame::Size2MiB(frame) => {
                    if offset != 0 {
                        unsafe {
                            _early_debug_panic(0xAFFE_0010_0000_0000, current.as_u64());
                        }
                        //return Err(());
                    }

                    /* FIXME: currently ok
                    if current + frame.size() > end {
                        unsafe {
                            _early_debug_panic(0xAFFE_0020_0000_0000, current.as_u64());
                        }
                        //return Err(());
                    }
                    */

                    match page_table.unmap(Page::<Size2MiB>::containing_address(current)) {
                        Ok((_frame, flush)) => flush.flush(),
                        Err(_) => {
                            unsafe {
                                _early_debug_panic(0xAFFE_0030_0000_0000, current.as_u64());
                            }
                            //return Err(());
                        }
                    }
                    frame.size()
                }
                MappedFrame::Size1GiB(frame) => {
                    if offset != 0 {
                        unsafe {
                            _early_debug_panic(0xAFFE_0100_0000_0000, current.as_u64());
                        }
                        //return Err(());
                    }

                    /* FIXME: currently ok
                    if current + frame.size() > end {
                        unsafe {
                            _early_debug_panic(0xAFFE_0200_0000_0000, current.as_u64());
                        }
                        //return Err(());
                    }
                    */

                    match page_table.unmap(Page::<Size1GiB>::containing_address(current)) {
                        Ok((_frame, flush)) => flush.flush(),
                        Err(_) => {
                            unsafe {
                                _early_debug_panic(0xAFFE_0300_0000_0000, current.as_u64());
                            }
                            //return Err(());
                        }
                    }
                    frame.size()
                }
            },
            TranslateResult::NotMapped => Page::<Size4KiB>::SIZE,
            TranslateResult::InvalidFrameAddress(_) => {
                unsafe {
                    _early_debug_panic(0xAFFE_2222_0000_0000, current.as_u64());
                }
                //return Err(());
            }
        }
    }
}

fn clear_c_bit_address_range(start: VirtAddr, end: VirtAddr, c_bit_mask: u64) -> Result<(), ()> {
    let mut page_table = paging::SHIM_PAGETABLE.write();
    let enc_phys_offset = EncPhysOffset::default();

    let mut current = start;
    loop {
        if current >= end {
            return Ok(());
        }
        let trans = page_table.translate(current);
        current += match trans {
            TranslateResult::Mapped {
                frame,
                flags: _,
                offset,
            } => match frame {
                MappedFrame::Size4KiB(frame) => {
                    if offset != 0 {
                        unsafe {
                            _early_debug_panic(0xAFFE_0000_0001_0000, current.as_u64());
                        }
                        //return Err(());
                    }
                    if current + frame.size() > end {
                        unsafe {
                            _early_debug_panic(0xAFFE_0000_0002_0000, current.as_u64());
                        }
                        //return Err(());
                    }

                    let page = Page::<Size4KiB>::containing_address(current);

                    let frame = page_table.level_4_table()[page.p4_index()].frame().unwrap();
                    let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                    let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                    let frame = page_table[page.p3_index()].frame().unwrap();
                    let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                    let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                    let frame = page_table[page.p2_index()].frame().unwrap();
                    let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                    let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                    let old_addr = page_table[page.p1_index()].addr();
                    let old_flags = page_table[page.p1_index()].flags();

                    page_table[page.p1_index()]
                        .set_addr(PhysAddr::new(old_addr.as_u64() & !c_bit_mask), old_flags);
                    flush(page.start_address());

                    frame.size()
                }
                MappedFrame::Size2MiB(frame) => {
                    if offset != 0 {
                        unsafe {
                            _early_debug_panic(0xAFFE_0000_0010_0000, current.as_u64());
                        }
                        //return Err(());
                    }
                    if current + frame.size() > end {
                        unsafe {
                            _early_debug_panic(0xAFFE_0000_0020_0000, current.as_u64());
                        }
                        //return Err(());
                    }
                    let page = Page::<Size2MiB>::containing_address(current);

                    let frame = page_table.level_4_table()[page.p4_index()].frame().unwrap();
                    let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                    let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                    let frame = page_table[page.p3_index()].frame().unwrap();
                    let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                    let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                    let old_addr = page_table[page.p2_index()].addr();
                    let old_flags = page_table[page.p2_index()].flags();

                    page_table[page.p2_index()]
                        .set_addr(PhysAddr::new(old_addr.as_u64() & !c_bit_mask), old_flags);
                    flush(page.start_address());

                    frame.size()
                }
                MappedFrame::Size1GiB(frame) => {
                    if offset != 0 {
                        unsafe {
                            _early_debug_panic(0xAFFE_0000_0100_0000, current.as_u64());
                        }
                        //return Err(());
                    }
                    if current + frame.size() > end {
                        unsafe {
                            _early_debug_panic(0xAFFE_0000_0200_0000, current.as_u64());
                        }
                        //return Err(());
                    }
                    let page = Page::<Size1GiB>::containing_address(current);

                    let frame = page_table.level_4_table()[page.p4_index()].frame().unwrap();
                    let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                    let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                    let old_addr = page_table[page.p3_index()].addr();
                    let old_flags = page_table[page.p3_index()].flags();

                    page_table[page.p3_index()]
                        .set_addr(PhysAddr::new(old_addr.as_u64() & !c_bit_mask), old_flags);
                    flush(page.start_address());

                    frame.size()
                }
            },
            TranslateResult::NotMapped => Page::<Size4KiB>::SIZE,
            TranslateResult::InvalidFrameAddress(_) => {
                unsafe {
                    _early_debug_panic(0xAFFE_3333_0000_0000, current.as_u64());
                }
                //return Err(());
            }
        }
    }
}
