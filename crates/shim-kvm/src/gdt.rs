// SPDX-License-Identifier: Apache-2.0

//! Global Descriptor Table init

use crate::shim_stack::{init_stack_with_guard, GuardedStack};
use crate::syscall::_syscall_enter;
use crate::thread::TcbRefCell;
use crate::{
    MAX_NUM_CPUS, SHIM_EX_STACK_SIZE, SHIM_EX_STACK_START, SHIM_STACK_SIZE, SHIM_STACK_START,
};

use alloc::boxed::Box;

use crate::hostcall::BlockGuard;
use x86_64::instructions::segmentation::{Segment, Segment64, CS, DS, ES, FS, GS, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::model_specific::{KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::paging::{Page, PageTableFlags, Size2MiB, Size4KiB};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::{align_up, VirtAddr};

/// Create an initial shim stack
pub fn initial_shim_stack(cpunum: usize) -> GuardedStack {
    assert!(cpunum < MAX_NUM_CPUS);
    let start = VirtAddr::new(
        SHIM_STACK_START + (cpunum as u64) * (SHIM_STACK_SIZE + Page::<Size2MiB>::SIZE),
    );
    assert!((start + SHIM_STACK_SIZE).as_u64() < SHIM_EX_STACK_START);
    init_stack_with_guard(start, SHIM_STACK_SIZE, PageTableFlags::empty())
}

#[cfg_attr(coverage, no_coverage)]
fn new_tss(cpunum: usize) -> &'static mut TaskStateSegment {
    assert!(cpunum < MAX_NUM_CPUS);
    let mut tss = Box::new(TaskStateSegment::new());

    // The current stack pointer top is in GS base
    tss.privilege_stack_table[0] = GS::read_base();

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
            let start = VirtAddr::new(SHIM_EX_STACK_START.checked_add(stack_offset).unwrap())
                + cpunum * 0x100_0000;

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
///
/// `unsafe` because the caller has to ensure it is only called once
/// and in a single-threaded context.
#[cfg_attr(coverage, no_coverage)]
pub unsafe fn init(cpunum: usize) {
    assert!(cpunum < MAX_NUM_CPUS);

    crate::eprintln!("[{cpunum}] init_gdt");

    let gdt = Box::leak(Box::new(GlobalDescriptorTable::new()));

    // `syscall` loads segments from STAR MSR assuming a data_segment follows `kernel_code_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let code = gdt.add_entry(Descriptor::kernel_code_segment());
    let data = gdt.add_entry(Descriptor::kernel_data_segment());

    // `sysret` loads segments from STAR MSR assuming `user_code_segment` follows `user_data_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let user_data = gdt.add_entry(Descriptor::user_data_segment());
    let user_code = gdt.add_entry(Descriptor::user_code_segment());

    let tss_selector = gdt.add_entry(Descriptor::tss_segment(new_tss(cpunum)));

    gdt.load();

    let kernel_stack = GS::read_base();

    // Setup the segment registers with the corresponding selectors
    CS::set_reg(code);
    SS::set_reg(data);
    load_tss(tss_selector);

    // Clear the other segment registers
    SS::set_reg(SegmentSelector(0));
    DS::set_reg(SegmentSelector(0));
    ES::set_reg(SegmentSelector(0));
    FS::set_reg(SegmentSelector(0));
    GS::set_reg(SegmentSelector(0));

    // Set the selectors to be set when userspace uses `syscall`
    Star::write(user_code, user_data, code, data).unwrap();

    // Set the pointer to the function to be called when userspace uses `syscall`
    LStar::write(VirtAddr::new(_syscall_enter as usize as u64));

    // Clear trap flag and interrupt enable
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::TRAP_FLAG);

    // Set the kernel gs base to the Tcb to be used in `_syscall_enter`
    let tcb = Box::new(TcbRefCell::new(kernel_stack, BlockGuard::new(cpunum)));
    let base = VirtAddr::from_ptr(Box::leak(tcb));
    KernelGsBase::write(base);
    GS::write_base(base);

    crate::eprintln!("[{cpunum}] init_gdt done");
}
