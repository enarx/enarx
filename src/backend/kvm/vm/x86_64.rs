// SPDX-License-Identifier: Apache-2.0

pub use kvm_bindings::kvm_segment as KvmSegment;
use memory::Page;
use x86_64::structures::paging::page_table::PageTable;

use std::mem::size_of_val;

#[repr(C)]
pub struct VMSetup<'a> {
    pub zero: &'a mut Page,
    pub shared_pages: &'a mut [Page],
    pub pml4t: &'a mut PageTable,
    pub pml3t_ident: &'a mut PageTable,
}

impl VMSetup<'_> {
    pub fn size(&self) -> usize {
        let addends = [
            size_of_val(self.zero),
            size_of_val(self.shared_pages),
            size_of_val(self.pml4t),
            size_of_val(self.pml3t_ident),
        ];

        addends.iter().sum()
    }
}
