// SPDX-License-Identifier: Apache-2.0

pub use kvm_bindings::kvm_segment as KvmSegment;
use memory::Page;
use x86_64::structures::paging::page_table::PageTable;

#[repr(C)]
pub struct VMSetup {
    pub zero_page: Page,
    pub shared_page: Page,
    pub pml4t: PageTable,
    pub pml3t_ident: PageTable,
}

impl Default for VMSetup {
    fn default() -> Self {
        VMSetup {
            zero_page: Page::default(),
            shared_page: Page::default(),
            pml4t: PageTable::new(),
            pml3t_ident: PageTable::new(),
        }
    }
}
