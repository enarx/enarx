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
