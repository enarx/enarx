// SPDX-License-Identifier: Apache-2.0

pub use kvm_bindings::kvm_segment as KvmSegment;
use primordial::Page;
use x86_64::structures::paging::page_table::PageTable;

#[repr(C)]
pub struct VMSetup<'a> {
    pub zero: &'a mut Page,
    pub shared_pages: &'a mut [Page],
    pub pml4t: &'a mut PageTable,
    pub pml3t_ident: &'a mut PageTable,
}
