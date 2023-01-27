// SPDX-License-Identifier: Apache-2.0

//! Helper functions for the shim stack

use crate::allocator::PageTableAllocatorLock;

use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

/// A guarded stack
pub struct GuardedStack {
    /// the stack pointer
    pub pointer: VirtAddr,
    /// the usable stack memory slice
    pub slice: &'static mut [u8],
}

/// Allocate a stack with guard pages
pub fn init_stack_with_guard(
    start: VirtAddr,
    stack_size: u64,
    extra_flags: PageTableFlags,
) -> GuardedStack {
    let mut allocator = PageTableAllocatorLock::new();

    // guard page
    // Safety: if the guard page is accessed, the kernel will panic
    unsafe {
        allocator.map_memory(
            PhysAddr::new(0),
            start - Page::<Size4KiB>::SIZE,
            Page::<Size4KiB>::SIZE as _,
            PageTableFlags::empty(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
    }
    .expect("Stack guard page mapping failed");

    let mem_slice = allocator
        .allocate_and_map_memory(
            start,
            stack_size as _,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | extra_flags,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | extra_flags,
        )
        .expect("Stack allocation failed");

    // guard page
    // Safety: if the guard page is accessed, the kernel will panic
    unsafe {
        allocator.map_memory(
            PhysAddr::new(0),
            start + stack_size,
            Page::<Size4KiB>::SIZE as _,
            PageTableFlags::empty(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
    }
    .expect("Stack guard page mapping failed");

    // Point to the end of the stack
    let stack_ptr = unsafe { mem_slice.as_ptr().add(mem_slice.len()) };

    // We know it's aligned to 16, so no need to manually align
    debug_assert_eq!((stack_ptr as u64).checked_rem(16), Some(0));

    GuardedStack {
        pointer: VirtAddr::from_ptr(stack_ptr),
        slice: mem_slice,
    }
}
