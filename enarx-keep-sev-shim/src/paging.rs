// SPDX-License-Identifier: Apache-2.0

//! Paging

use crate::addr::SHIM_VIRT_OFFSET;

use x86_64::structures::paging::{OffsetPageTable, PageTable};
use x86_64::VirtAddr;

use crate::rwlock_singleton;

rwlock_singleton! {
    static mut SHIM_PAGETABLE: ShimPageTableRWLock<OffsetPageTable<'static>>;
}

impl ShimPageTableRWLock {
    /// Initialize a new OffsetPageTable.
    ///
    /// This function is unsafe because the caller must guarantee that the
    /// complete physical memory is mapped to virtual memory at the passed
    /// `physical_memory_offset`. Also, this function must be only called once
    /// to avoid aliasing `&mut` references (which is undefined behavior).
    ///
    /// # Safety
    ///
    /// This function is unsafe because the caller must guarantee that the
    /// complete physical memory is mapped to virtual memory at the passed
    /// `physical_memory_offset`.
    pub unsafe fn init() {
        let physical_memory_offset = VirtAddr::new(SHIM_VIRT_OFFSET as u64);
        let level_4_table = ShimPageTableRWLock::active_level_4_table(physical_memory_offset);
        ShimPageTableRWLock::init_global(OffsetPageTable::new(
            level_4_table,
            physical_memory_offset,
        ));
    }

    /// Returns a mutable reference to the active level 4 table.
    ///
    /// This function is unsafe because the caller must guarantee that the
    /// complete physical memory is mapped to virtual memory at the passed
    /// `physical_memory_offset`. Also, this function must be only called once
    /// to avoid aliasing `&mut` references (which is undefined behavior).
    unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
        use x86_64::registers::control::Cr3;

        let (level_4_table_frame, _) = Cr3::read();

        let phys = level_4_table_frame.start_address();
        let virt = physical_memory_offset + phys.as_u64();
        let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

        &mut *page_table_ptr // unsafe
    }
}
