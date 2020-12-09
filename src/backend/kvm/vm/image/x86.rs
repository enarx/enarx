// SPDX-License-Identifier: Apache-2.0

//! Architecture-specific setup for x86_64 VMs.

use mmarinus::{perms::ReadWrite, Map};
use primordial::Page;
use x86_64::structures::paging::page_table::{PageTable, PageTableFlags};
use x86_64::VirtAddr;

use crate::backend::kvm::Hook;

use super::Arch;

/// The x86_64 shim expects the first page to be a zero page, followed by
/// the page tables.
#[repr(C, align(4096))]
pub struct X86 {
    pub zero: Page,
    pub pml4t: PageTable,
    pub pml3t_ident: PageTable,
}

impl Arch for X86 {
    fn commit(&mut self, backing: &Map<ReadWrite>, hook: &impl Hook) {
        use PageTableFlags as Flags;

        let start = VirtAddr::new(backing.addr() as u64);
        let hv2gp = hook.hv2gp();

        let pml3t_ident_addr = VirtAddr::new(&self.pml3t_ident as *const _ as u64);
        let pdpte = hv2gp(pml3t_ident_addr, start);
        self.pml4t[0].set_addr(pdpte, Flags::WRITABLE | Flags::PRESENT);

        let pml3t_addr = hv2gp(start, start);
        let flags = Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT;
        self.pml3t_ident[0].set_addr(pml3t_addr, flags);
    }
}
