// SPDX-License-Identifier: Apache-2.0

//! Initial Page Tables
//!
//! * PDT_IDENT: an identity mapped one for 0x0 - 0x60_0000
//! * PDPT_OFFSET: an offset page table with offset $SHIM_OFFSET

use crate::addr::SHIM_VIRT_OFFSET;
use crate::addr::{BYTES_2_GIB, BYTES_2_MIB};
use crate::paging;
use array_const_fn_init::array_const_fn_init;
use x86_64::instructions::tlb::flush;
use x86_64::structures::paging::{Mapper, Page, PageTableFlags, Size2MiB};
use x86_64::VirtAddr;

/// A page-aligned Page Table.
#[repr(C, align(4096))]
pub struct AlignedPageTable(pub [u64; 512]);

const HUGE_PAGE_TABLE_FLAGS: u64 = PageTableFlags::HUGE_PAGE.bits()
    | PageTableFlags::WRITABLE.bits()
    | PageTableFlags::PRESENT.bits();

#[allow(clippy::integer_arithmetic)]
const fn gen_2mb_pdt_entries(i: usize) -> u64 {
    let base: u64 = HUGE_PAGE_TABLE_FLAGS;
    let step: u64 = BYTES_2_MIB;
    base + (i as u64) * step
}

#[allow(clippy::integer_arithmetic)]
const fn gen_2gb_pdpt_entries(i: usize) -> u64 {
    let base: u64 = HUGE_PAGE_TABLE_FLAGS;
    let step: u64 = BYTES_2_GIB;
    base + (i as u64) * step
}

/// The root table of the 4-Level Paging
///
/// Intel Vol 3A - 4.5
/// will contain:
///       [0] PDPT_IDENT:  0x0                   - 0x80_0000_0000
/// [1..=510] empty for now
///     [511] PDPT_OFFSET: 0xFFFF_FF80_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF
#[no_mangle]
pub static mut PML4T: AlignedPageTable = AlignedPageTable([0; 512]);

/// Offset Page-Directory-Pointer Table
///
/// with pointers to Huge Pages, mapping 38bit of addresses to
/// SHIM_OFFSET + x, making the translation of shim virtual address space
/// to physical address space easy, by substracting SHIM_OFFSET.
/// This also enables mapping user space below SHIM_OFFSET and use the same
/// CR3 for shim and user space.
#[no_mangle]
pub static mut PDPT_OFFSET: AlignedPageTable =
    AlignedPageTable(array_const_fn_init![gen_2gb_pdpt_entries; 512]);

/// Offset Page-Directory Table
#[no_mangle]
pub static mut PDT_OFFSET: AlignedPageTable =
    AlignedPageTable(array_const_fn_init![gen_2mb_pdt_entries; 512]);

/// Identity Page-Directory-Pointer Table
///
/// will contain a pointer to a Identity Page-Directory Table
///      [0] PDT_IDENT:  0x0                   - 0x4000_0000
/// [1..512] empty for now
#[no_mangle]
pub static mut PDPT_IDENT: AlignedPageTable = AlignedPageTable([0; 512]);

#[allow(clippy::integer_arithmetic)]
const fn pdt_ident_entry(i: usize) -> u64 {
    match i {
        0 => HUGE_PAGE_TABLE_FLAGS,
        1 => HUGE_PAGE_TABLE_FLAGS + BYTES_2_MIB,
        2 => HUGE_PAGE_TABLE_FLAGS + BYTES_2_MIB * 2,
        _ => 0,
    }
}

/// Identity Page-Directory Table
///
/// with 6 pointers to 2MB Huge Pages
///  [0..=2] 0x0 - 0x60_0000
/// [3..512] empty for now
#[no_mangle]
pub static mut PDT_IDENT: AlignedPageTable =
    AlignedPageTable(array_const_fn_init![pdt_ident_entry; 512]);

/// Map the sallyport Block pages to unencrypted memory.
pub fn switch_sallyport_to_unencrypted(c_bit_mask: u64) {
    let mut page_table = paging::SHIM_PAGETABLE.write();

    // Unmap the first 2MB page in the encrypted kernel address space,
    // because a VM is not supposed to map the same physical memory
    // encrypted and unencrypted.
    page_table
        .unmap(Page::<Size2MiB>::containing_address(VirtAddr::new(
            SHIM_VIRT_OFFSET,
        )))
        .map(|(_, flush)| flush.flush())
        .unwrap();

    unsafe {
        if c_bit_mask != 0 {
            // Clear the C-Bit in the first 2MB identity page entry
            // making the sallyport Block pages unencrypted.
            PDT_IDENT.0[0] &= !c_bit_mask;
            flush(VirtAddr::new(0x000000));
        }

        // Unmap the second and third 2MB page in the identity address space
        PDT_IDENT.0[1] = 0;
        flush(VirtAddr::new(0x200000));
        PDT_IDENT.0[2] = 0;
        flush(VirtAddr::new(0x400000));
    }
}
