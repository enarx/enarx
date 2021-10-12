// SPDX-License-Identifier: Apache-2.0

//! Paging

use crate::addr::SHIM_VIRT_OFFSET;
use crate::snp::get_cbit_mask;

use spinning::{Lazy, RwLock};
use x86_64::registers::control::Cr3;
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
            offset: VirtAddr::new(SHIM_VIRT_OFFSET as u64),
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

/// The global `MappedPageTable` of the shim for encrypted pages.
pub static SHIM_PAGETABLE: Lazy<RwLock<MappedPageTable<'static, EncPhysOffset>>> =
    Lazy::new(|| {
        let enc_phys_offset = EncPhysOffset::default();

        let enc_offset_page_table = unsafe {
            let level_4_table_ptr = enc_phys_offset.frame_to_pointer(Cr3::read().0);

            MappedPageTable::new(&mut *level_4_table_ptr, enc_phys_offset)
        };

        RwLock::<MappedPageTable<'static, EncPhysOffset>>::const_new(
            spinning::RawRwLock::const_new(),
            enc_offset_page_table,
        )
    });
