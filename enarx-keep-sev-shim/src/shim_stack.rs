// SPDX-License-Identifier: Apache-2.0

//! Helper functions for the shim stack

use crate::frame_allocator::FRAME_ALLOCATOR;
use crate::paging::SHIM_PAGETABLE;
use crate::{dbg, eprintln};
use core::ops::{Deref, DerefMut};
use units::bytes;
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

/// The virtual address of the main kernel stack
pub const SHIM_STACK_START: u64 = 0xFFFF_FF48_4800_0000;

/// The size of the main kernel stack
#[allow(clippy::integer_arithmetic)]
pub const SHIM_STACK_SIZE: u64 = bytes![4; MiB];

/// Allocate the stack for the shim with guard pages
#[allow(clippy::integer_arithmetic)]
pub fn init_shim_stack() -> VirtAddr {
    dbg!(FRAME_ALLOCATOR.read().deref());

    // guard page
    FRAME_ALLOCATOR
        .write()
        .allocate_and_map_memory(
            SHIM_PAGETABLE.write().deref_mut(),
            VirtAddr::new(SHIM_STACK_START - Page::<Size4KiB>::SIZE),
            Page::<Size4KiB>::SIZE as _,
            PageTableFlags::empty(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
        .expect("Stack guard page allocation failed");

    dbg!(FRAME_ALLOCATOR.read().deref());

    let mem_slice = FRAME_ALLOCATOR
        .write()
        .allocate_and_map_memory(
            SHIM_PAGETABLE.write().deref_mut(),
            VirtAddr::new(SHIM_STACK_START),
            SHIM_STACK_SIZE as _,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
        .expect("Stack allocation failed");

    dbg!(FRAME_ALLOCATOR.read().deref());

    // guard page
    FRAME_ALLOCATOR
        .write()
        .allocate_and_map_memory(
            SHIM_PAGETABLE.write().deref_mut(),
            VirtAddr::new(SHIM_STACK_START + SHIM_STACK_SIZE),
            Page::<Size4KiB>::SIZE as _,
            PageTableFlags::empty(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
        .expect("Stack guard page allocation failed");

    dbg!(FRAME_ALLOCATOR.read().deref());
    // Test, if we can write to it.
    dbg!(&mem_slice.as_ptr());
    dbg!(&mem_slice[0]);
    dbg!(&mem_slice[mem_slice.len() - 1]);
    mem_slice.iter_mut().for_each(|p| *p = 127);
    dbg!(&mem_slice[0]);
    dbg!(&mem_slice[mem_slice.len() - 1]);

    // Point to the end of the stack
    let stack_ptr = unsafe { mem_slice.as_ptr().offset(SHIM_STACK_SIZE as _) };

    eprintln!("kernel_stack_ptr = {:#?}", stack_ptr);

    // We know it's aligned to 16, so no need to manually align
    VirtAddr::from_ptr(stack_ptr)
}
