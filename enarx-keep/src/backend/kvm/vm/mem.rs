// SPDX-License-Identifier: Apache-2.0

use crate::backend::kvm::vm::x86_64::VMSetup;

pub use kvm_bindings::kvm_userspace_memory_region as KvmUserspaceMemoryRegion;
use lset::Span;
use mmarinus::{perms, Map};
use primordial::Page;
use x86_64::structures::paging::page_table::PageTable;
use x86_64::{PhysAddr, VirtAddr};

use std::mem::{size_of, size_of_val};
use std::slice::from_raw_parts_mut;

pub struct Region {
    num_sally_pages: usize,
    kvm_region: KvmUserspaceMemoryRegion,
    _backing: Map<perms::ReadWrite>,
}

impl Region {
    pub fn new(
        num_sally_pages: usize,
        kvm_region: KvmUserspaceMemoryRegion,
        backing: Map<perms::ReadWrite>,
    ) -> Self {
        Self {
            num_sally_pages,
            kvm_region,
            _backing: backing,
        }
    }

    pub fn as_guest(&self) -> Span<PhysAddr, u64> {
        Span {
            start: PhysAddr::new(self.kvm_region.guest_phys_addr),
            count: self.kvm_region.memory_size,
        }
    }

    pub fn as_virt(&self) -> Span<VirtAddr, u64> {
        Span {
            start: VirtAddr::new(self.kvm_region.userspace_addr),
            count: self.kvm_region.memory_size,
        }
    }

    pub fn size_of_setup(num_sally_pages: usize) -> usize {
        let mut size: usize = 0;
        size += Page::size();
        size += Page::size() * num_sally_pages;
        size += size_of::<PageTable>();
        size += size_of::<PageTable>();
        size
    }

    pub fn prefix_mut(&self) -> VMSetup<'_> {
        let mut dst = self.as_virt().start;

        let zero = unsafe { &mut *dst.as_mut_ptr::<Page>() };
        dst += size_of_val(zero);

        let shared = unsafe { from_raw_parts_mut(dst.as_mut_ptr::<Page>(), self.num_sally_pages) };
        dst += size_of_val(shared);

        let pml4t = unsafe { &mut *dst.as_mut_ptr::<PageTable>() };
        dst += size_of_val(pml4t);

        let pml3t_ident = unsafe { &mut *dst.as_mut_ptr::<PageTable>() };
        dst += size_of_val(pml3t_ident);

        VMSetup {
            zero,
            shared_pages: shared,
            pml4t,
            pml3t_ident,
        }
    }
}
