// SPDX-License-Identifier: Apache-2.0

//! Global Descriptor Table init

use crate::shim_stack::init_stack_with_guard;
use crate::syscall::_syscall_enter;
use crate::{SHIM_EX_STACK_SIZE, SHIM_EX_STACK_START};

use alloc::boxed::Box;

use x86_64::instructions::segmentation::{Segment, Segment64, CS, DS, ES, FS, GS, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::model_specific::{KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::paging::{Page, PageTableFlags, Size2MiB, Size4KiB};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::{align_up, VirtAddr};

#[cfg_attr(coverage, no_coverage)]
fn new_tss(stack_pointer: VirtAddr) -> &'static mut TaskStateSegment {
    let mut tss = Box::new(TaskStateSegment::new());

    tss.privilege_stack_table[0] = stack_pointer;

    let ptr_interrupt_stack_table = core::ptr::addr_of_mut!(tss.interrupt_stack_table);
    let mut interrupt_stack_table = unsafe { ptr_interrupt_stack_table.read_unaligned() };

    // Assign the stacks for the exceptions and interrupts
    interrupt_stack_table
        .iter_mut()
        .enumerate()
        .for_each(|(idx, p)| {
            let offset: u64 = align_up(
                SHIM_EX_STACK_SIZE
                    .checked_add(Page::<Size4KiB>::SIZE.checked_mul(2).unwrap())
                    .unwrap(),
                Page::<Size2MiB>::SIZE,
            );

            let stack_offset = offset.checked_mul(idx as _).unwrap();
            let start = VirtAddr::new(SHIM_EX_STACK_START.checked_add(stack_offset).unwrap());

            *p = init_stack_with_guard(start, SHIM_EX_STACK_SIZE, PageTableFlags::empty()).pointer;
        });

    unsafe {
        ptr_interrupt_stack_table.write_unaligned(interrupt_stack_table);
    }

    Box::leak(tss)
}

/// Initialize the GDT
///
/// # Safety
/// The caller has to ensure that the stack pointer is valid and 16 byte aligned.
#[cfg_attr(coverage, no_coverage)]
pub unsafe fn init(stack_pointer: VirtAddr) {
    #[cfg(debug_assertions)]
    crate::eprintln!("init_gdt");

    let gdt = Box::leak(Box::new(GlobalDescriptorTable::new()));
    let tss = new_tss(stack_pointer);
    // `syscall` loads segments from STAR MSR assuming a data_segment follows `kernel_code_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let code = gdt.add_entry(Descriptor::kernel_code_segment());
    let data = gdt.add_entry(Descriptor::kernel_data_segment());

    // `sysret` loads segments from STAR MSR assuming `user_code_segment` follows `user_data_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let user_data = gdt.add_entry(Descriptor::user_data_segment());
    let user_code = gdt.add_entry(Descriptor::user_code_segment());

    let tss_selector = gdt.add_entry(Descriptor::tss_segment(tss));

    gdt.load();

    // Safety: the segment register are not yet in use for this CPU
    unsafe {
        // Setup the segment registers with the corresponding selectors
        CS::set_reg(code);
        SS::set_reg(data);
        load_tss(tss_selector);

        // Clear the other segment registers
        DS::set_reg(SegmentSelector(0));
        ES::set_reg(SegmentSelector(0));
        FS::set_reg(SegmentSelector(0));
        GS::set_reg(SegmentSelector(0));
    }

    // Set the selectors to be set when userspace uses `syscall`
    Star::write(user_code, user_data, code, data).unwrap();

    // Set the pointer to the function to be called when userspace uses `syscall`
    LStar::write(VirtAddr::new(_syscall_enter as usize as u64));

    // Clear trap flag and interrupt enable
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::TRAP_FLAG);

    // Set the kernel gs base to the TSS to be used in `_syscall_enter`
    let base = VirtAddr::from_ptr(tss);
    KernelGsBase::write(base);

    // Safety: the GS base is not yet in use, because no syscalls happened yet for this CPU
    unsafe {
        GS::write_base(base);
    }

    crate::eprintln!("init_gdt done");
}
