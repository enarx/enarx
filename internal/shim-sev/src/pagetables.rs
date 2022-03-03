// SPDX-License-Identifier: Apache-2.0

//! Page Tables

use core::alloc::Layout;
use core::mem::size_of;

use array_const_fn_init::array_const_fn_init;
use x86_64::instructions::tlb::{flush, flush_all};
use x86_64::structures::paging::mapper::{MappedFrame, PageTableFrameMapping, TranslateResult};
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{
    Page, PageTable, PageTableFlags, Size1GiB, Size2MiB, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::addr::{BYTES_1_GIB, BYTES_2_MIB, SHIM_VIRT_OFFSET};
use crate::allocator::ALLOCATOR;
use crate::paging;
use crate::paging::{EncPhysOffset, SHIM_PAGETABLE};
use crate::snp::get_cbit_mask;
use crate::spin::RacyCell;

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
/// will contain:
///       [0] Identity:    0x0000_0000_0000_0000..=0x0000_0000_FFFF_FFFF
///           only until the initial setup phase, then removed
/// [1..=510] empty for now
///     [511] Offset:      0xFFFF_FF80_0000_0000..=0xFFFF_FFFF_FFFF_FFFF
#[no_mangle]
#[link_section = ".entry64_data"]
pub static PML4T: RacyCell<AlignedPageTable> = RacyCell::new(AlignedPageTable([0; 512]));

/// Page-Directory-Pointer Table
///
/// with pointers to Huge Pages, mapping 38bit of addresses to
/// SHIM_OFFSET + x, making the translation of shim virtual address space
/// to physical address space easy, by substracting SHIM_OFFSET.
/// This also enables mapping user space below SHIM_OFFSET and use the same
/// CR3 for shim and user space.
#[no_mangle]
#[link_section = ".entry64_data"]
pub static PDPT: RacyCell<AlignedPageTable> = RacyCell::new(AlignedPageTable(
    array_const_fn_init![gen_1gb_pdpt_entries; 512],
));

/// Page-Directory Table for 0xC000_0000..=0xFFFF_FFFF
#[no_mangle]
#[link_section = ".entry64_data"]
pub static PDT_C000_0000: RacyCell<AlignedPageTable> = RacyCell::new(AlignedPageTable(
    array_const_fn_init![gen_2mb_pdt_entries_c000_0000; 512],
));

/// 4k Page Table for 0xFFE0_0000..=0xFFFF_FFFF
#[no_mangle]
#[link_section = ".entry64_data"]
pub static PT_FFE0_0000: RacyCell<AlignedPageTable> = RacyCell::new(AlignedPageTable(
    array_const_fn_init![gen_4k_pt_entries_ffe0_0000; 512],
));

/// Unmap the initial identity mapping for 0xC000_0000..=0xFFFF_FFFF
pub fn unmap_identity() {
    SHIM_PAGETABLE.write().level_4_table()[0] = PageTableEntry::new();
    flush_all();
}

/// Error returned by this module
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The given virtual address is not mapped to a physical frame.
    NotMapped,
    /// The page table entry for the given virtual address points to an invalid physical address.
    InvalidFrameAddress(PhysAddr),
    /// The given virtual address is not page aligned.
    NotAligned,
}

/// smash the pagetable entries to 4k pages
pub fn smash(addr: VirtAddr) -> Result<(), Error> {
    let trans = paging::SHIM_PAGETABLE.write().translate(addr);
    match trans {
        TranslateResult::Mapped {
            frame,
            flags: _,
            offset: _,
        } => match frame {
            MappedFrame::Size4KiB(_frame) => Ok(()),
            MappedFrame::Size2MiB(_frame) => {
                let page = Page::<Size2MiB>::containing_address(addr);
                let new_pagetable: &mut PageTable = unsafe {
                    &mut *(ALLOCATOR
                        .write()
                        .try_alloc(Layout::from_size_align_unchecked(
                            size_of::<PageTable>(),
                            Page::<Size4KiB>::SIZE as _,
                        ))
                        .unwrap()
                        .as_ptr() as *mut PageTable)
                };

                {
                    let c_bit_mask = get_cbit_mask();
                    let enc_phys_offset = EncPhysOffset::default();
                    let mut page_table = SHIM_PAGETABLE.write();
                    let frame = page_table.level_4_table()[page.p4_index()].frame().unwrap();
                    let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                    let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                    let frame = page_table[page.p3_index()].frame().unwrap();
                    let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                    let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                    let index = page.p2_index();

                    let old_addr = page_table[index].addr();
                    let old_flags = page_table[index].flags() & (!PageTableFlags::HUGE_PAGE);

                    new_pagetable.iter_mut().enumerate().for_each(|(i, e)| {
                        e.set_addr(
                            old_addr + i.checked_mul(Page::<Size4KiB>::SIZE as usize).unwrap(),
                            old_flags,
                        );
                    });

                    let new_pagetable_pa = PhysAddr::new(
                        (VirtAddr::from_ptr(new_pagetable) - SHIM_VIRT_OFFSET).as_u64(),
                    );

                    page_table[index].set_addr(
                        PhysAddr::new(new_pagetable_pa.as_u64() | (old_addr.as_u64() & c_bit_mask)),
                        old_flags,
                    );

                    flush(page.start_address());
                }
                Ok(())
            }
            MappedFrame::Size1GiB(_frame) => {
                let page = Page::<Size1GiB>::containing_address(addr);
                let new_pagetable: &mut PageTable = unsafe {
                    &mut *(ALLOCATOR
                        .write()
                        .try_alloc(Layout::from_size_align_unchecked(
                            size_of::<PageTable>(),
                            Page::<Size4KiB>::SIZE as _,
                        ))
                        .unwrap()
                        .as_ptr() as *mut PageTable)
                };

                {
                    let c_bit_mask = get_cbit_mask();
                    let enc_phys_offset = EncPhysOffset::default();

                    let mut page_table = SHIM_PAGETABLE.write();

                    let frame = page_table.level_4_table()[page.p4_index()].frame().unwrap();
                    let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                    let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                    let index = page.p3_index();

                    let old_addr = page_table[index].addr();
                    let old_flags = page_table[index].flags();

                    new_pagetable.iter_mut().enumerate().for_each(|(i, e)| {
                        e.set_addr(
                            old_addr + i.checked_mul(Page::<Size2MiB>::SIZE as usize).unwrap(),
                            old_flags,
                        );
                    });

                    let new_pagetable_pa = PhysAddr::new(
                        (VirtAddr::from_ptr(new_pagetable) - SHIM_VIRT_OFFSET).as_u64(),
                    );

                    page_table[index].set_addr(
                        PhysAddr::new(new_pagetable_pa.as_u64() | (old_addr.as_u64() & c_bit_mask)),
                        old_flags & (!PageTableFlags::HUGE_PAGE),
                    );

                    flush(page.start_address());
                    Ok(())
                }
            }
        },
        TranslateResult::NotMapped => Err(Error::NotMapped),
        TranslateResult::InvalidFrameAddress(addr) => Err(Error::InvalidFrameAddress(addr)),
    }
}

/// clear the c_bit
pub fn clear_c_bit_address_range(start: VirtAddr, end: VirtAddr) -> Result<(), Error> {
    let c_bit_mask = get_cbit_mask();

    let enc_phys_offset = EncPhysOffset::default();

    let mut current = start;
    loop {
        if current >= end {
            return Ok(());
        }
        let trans = paging::SHIM_PAGETABLE.write().translate(current);

        current += match trans {
            TranslateResult::Mapped {
                frame,
                flags: _,
                offset,
            } => match frame {
                MappedFrame::Size4KiB(frame) => {
                    if offset != 0 {
                        return Err(Error::NotAligned);
                    }

                    if current + frame.size() > end {
                        return Err(Error::NotAligned);
                    }

                    let page = Page::<Size4KiB>::containing_address(current);

                    {
                        let mut page_table = SHIM_PAGETABLE.write();
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
                    }
                    frame.size()
                }
                MappedFrame::Size2MiB(frame) => {
                    if offset != 0 || current + frame.size() > end {
                        smash(current)?;
                        return clear_c_bit_address_range(current, end);
                    }

                    let page = Page::<Size2MiB>::containing_address(current);
                    {
                        let mut page_table = SHIM_PAGETABLE.write();
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
                    }
                    frame.size()
                }
                MappedFrame::Size1GiB(frame) => {
                    if offset != 0 || current + frame.size() > end {
                        smash(current)?;
                        return clear_c_bit_address_range(current, end);
                    }

                    let page = Page::<Size1GiB>::containing_address(current);
                    {
                        let mut page_table = SHIM_PAGETABLE.write();
                        let frame = page_table.level_4_table()[page.p4_index()].frame().unwrap();
                        let page_table_ptr = enc_phys_offset.frame_to_pointer(frame);
                        let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

                        let old_addr = page_table[page.p3_index()].addr();
                        let old_flags = page_table[page.p3_index()].flags();

                        page_table[page.p3_index()]
                            .set_addr(PhysAddr::new(old_addr.as_u64() & !c_bit_mask), old_flags);
                        flush(page.start_address());
                    }
                    frame.size()
                }
            },
            TranslateResult::NotMapped => Page::<Size4KiB>::SIZE,
            TranslateResult::InvalidFrameAddress(addr) => {
                return Err(Error::InvalidFrameAddress(addr));
            }
        }
    }
}
