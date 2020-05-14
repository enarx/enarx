// SPDX-License-Identifier: Apache-2.0

use x86_64::structures::paging::page_table::PageTable;

/// The *guest* physical address of the root page table structure.
pub const PML4_START: u64 = 0x9000;

/// The first page table entry.
pub const PDPTE_START: u64 = 0xA000;

// The one provided by x86_64 understandably does not impl std::error::Error.
#[derive(Copy, Clone, Debug)]
pub struct PhysAddrNotValid(pub u64);
impl std::error::Error for PhysAddrNotValid {}

impl std::fmt::Display for PhysAddrNotValid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}({:#x})", "PhysAddrNotValid", self.0)
    }
}

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
