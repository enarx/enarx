// SPDX-License-Identifier: Apache-2.0

pub use kvm_bindings::kvm_segment as KvmSegment;
use x86_64::structures::paging::page_table::PageTable;
use x86_64::PhysAddr;

/// The *guest* physical address of the root page table structure.
pub const PML4_START: PhysAddr = PhysAddr::new_truncate(0x9000);

/// The first page table entry.
pub const PDPTE_START: PhysAddr = PhysAddr::new_truncate(0xA000);

#[repr(C)]
pub struct PageTables {
    pub pml4t: PageTable,
    pub pml3t_ident: PageTable,
}

impl Default for PageTables {
    fn default() -> Self {
        PageTables {
            pml4t: PageTable::new(),
            pml3t_ident: PageTable::new(),
        }
    }
}
