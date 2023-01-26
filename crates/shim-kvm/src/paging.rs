// SPDX-License-Identifier: Apache-2.0

//! Paging

use crate::addr::SHIM_VIRT_OFFSET;
use crate::snp::get_cbit_mask;

use crate::pagetables::PML4T;
use spin::{Lazy, RwLock};
use x86_64::structures::paging::mapper::PageTableFrameMapping;
use x86_64::structures::paging::{MappedPageTable, PageTable, PhysFrame};
use x86_64::VirtAddr;

/// A `PageTableFrameMapping` specialized to encrypted physical pages.
#[derive(Debug)]
pub struct EncPhysOffset {
    /// The virtual address of physical address `0` (without the C-Bit)
    pub offset: VirtAddr,
    /// The C-Bit mask indicating encrypted physical pages
    pub c_bit_mask: u64,
}

impl Default for EncPhysOffset {
    fn default() -> Self {
        EncPhysOffset {
            offset: VirtAddr::new(SHIM_VIRT_OFFSET),
            c_bit_mask: get_cbit_mask(),
        }
    }
}

unsafe impl PageTableFrameMapping for EncPhysOffset {
    fn frame_to_pointer(&self, frame: PhysFrame) -> *mut PageTable {
        let phys_start_address = frame.start_address().as_u64();
        assert_eq!(phys_start_address & self.c_bit_mask, self.c_bit_mask);
        let virt = self.offset + (phys_start_address & !self.c_bit_mask);
        virt.as_mut_ptr()
    }
}

/// The shim's page table type
pub type ShimPageTable = MappedPageTable<'static, EncPhysOffset>;

/// The global `MappedPageTable` of the shim for encrypted pages.
pub static SHIM_PAGETABLE: Lazy<RwLock<ShimPageTable>> = Lazy::new(|| {
    let enc_phys_offset = EncPhysOffset::default();

    let enc_offset_page_table =
        unsafe { MappedPageTable::new(&mut (*(PML4T.get() as *mut PageTable)), enc_phys_offset) };

    RwLock::new(enc_offset_page_table)
});
