// SPDX-License-Identifier: Apache-2.0

//! Global Descriptor Table init

use crate::shim_stack::{init_stack_with_guard, GuardedStack};
use crate::syscall::_syscall_enter;
use crate::{SHIM_EX_STACK_SIZE, SHIM_EX_STACK_START, SHIM_STACK_SIZE, SHIM_STACK_START};

use core::ops::Deref;

use spin::Lazy;
use x86_64::instructions::segmentation::{Segment, Segment64, CS, DS, ES, FS, GS, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::model_specific::{KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::paging::{Page, PageTableFlags, Size2MiB, Size4KiB};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::{align_up, VirtAddr};

#[cfg_attr(coverage, no_coverage)]
fn lazy_initial_stack() -> GuardedStack {
    init_stack_with_guard(
        VirtAddr::new(SHIM_STACK_START),
        SHIM_STACK_SIZE,
        PageTableFlags::empty(),
    )
}

/// The initial shim stack
pub static INITIAL_STACK: Lazy<GuardedStack> = Lazy::new(lazy_initial_stack);

#[cfg_attr(coverage, no_coverage)]
fn lazy_tss() -> TaskStateSegment {
    let mut tss = TaskStateSegment::new();

    tss.privilege_stack_table[0] = INITIAL_STACK.pointer;

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

    tss
}

/// The global TSS
pub static TSS: Lazy<TaskStateSegment> = Lazy::new(lazy_tss);

/// The Selectors used in the GDT setup
pub struct Selectors {
    /// shim code selector
    pub code: SegmentSelector,
    /// shim data selector
    pub data: SegmentSelector,
    /// exec data selector
    pub user_data: SegmentSelector,
    /// exec code selector
    pub user_code: SegmentSelector,
    /// TSS selector
    pub tss: SegmentSelector,
}

#[cfg_attr(coverage, no_coverage)]
fn lazy_gdt() -> (GlobalDescriptorTable, Selectors) {
    let mut gdt = GlobalDescriptorTable::new();

    // `syscall` loads segments from STAR MSR assuming a data_segment follows `kernel_code_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let code = gdt.add_entry(Descriptor::kernel_code_segment());

    let data = gdt.add_entry(Descriptor::kernel_data_segment());

    // `sysret` loads segments from STAR MSR assuming `user_code_segment` follows `user_data_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let user_data = gdt.add_entry(Descriptor::user_data_segment());
    let user_code = gdt.add_entry(Descriptor::user_code_segment());

    // Important: TSS.deref() != &TSS because of lazy_static
    let tss = gdt.add_entry(Descriptor::tss_segment(TSS.deref()));

    let selectors = Selectors {
        code,
        data,
        user_data,
        user_code,
        tss,
    };

    (gdt, selectors)
}

/// The global GDT
pub static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(lazy_gdt);

/// Initialize the GDT
///
/// # Safety
///
/// `unsafe` because the caller has to ensure it is only called once
/// and in a single-threaded context.
#[cfg_attr(coverage, no_coverage)]
pub unsafe fn init() {
    #[cfg(debug_assertions)]
    crate::eprintln!("init_gdt");

    GDT.0.load();

    // Setup the segment registers with the corresponding selectors
    CS::set_reg(GDT.1.code);
    SS::set_reg(GDT.1.data);
    load_tss(GDT.1.tss);

    // Clear the other segment registers
    SS::set_reg(SegmentSelector(0));
    DS::set_reg(SegmentSelector(0));
    ES::set_reg(SegmentSelector(0));
    FS::set_reg(SegmentSelector(0));
    GS::set_reg(SegmentSelector(0));

    // Set the selectors to be set when userspace uses `syscall`
    Star::write(GDT.1.user_code, GDT.1.user_data, GDT.1.code, GDT.1.data).unwrap();

    // Set the pointer to the function to be called when userspace uses `syscall`
    LStar::write(VirtAddr::new(_syscall_enter as usize as u64));

    // Clear trap flag and interrupt enable
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::TRAP_FLAG);

    // Set the kernel gs base to the TSS to be used in `_syscall_enter`
    // Important: TSS.deref() != &TSS because of lazy_static
    let base = VirtAddr::new(TSS.deref() as *const _ as u64);
    KernelGsBase::write(base);
    GS::write_base(base);
}
