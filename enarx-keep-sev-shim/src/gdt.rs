// SPDX-License-Identifier: Apache-2.0

//! Global Descriptor Table init

use crate::eprintln;
use crate::syscall::_syscall_enter;
use memory::Page;
use x86_64::instructions::segmentation::{load_ds, load_es, load_fs, load_gs, load_ss, set_cs};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::model_specific::{KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::{
    Descriptor, DescriptorFlags, GlobalDescriptorTable, SegmentSelector,
};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::{PrivilegeLevel, VirtAddr};

const STACK_NUM_PAGES: usize = 5;
static mut STACKS: [[Page; STACK_NUM_PAGES]; 7] = [[Page::zeroed(); STACK_NUM_PAGES]; 7];

pub(crate) static mut TSS: TaskStateSegment = TaskStateSegment::new();
pub(crate) static mut GDT: GlobalDescriptorTable = GlobalDescriptorTable::new();

/// The user data segment
///
/// For performance and simplicity reasons, this is a constant
/// in the assembler code and here for debug_assert!()
const USER_DATA_SEGMENT_INDEX: u64 = 3;
const USER_DATA_SEGMENT: u64 = (USER_DATA_SEGMENT_INDEX << 3) | (PrivilegeLevel::Ring3 as u64);

/// The user code segment
///
/// For performance and simplicity reasons, this is a constant
/// in the assembler code and here for debug_assert!()
const USER_CODE_SEGMENT_INDEX: u64 = 4;
const USER_CODE_SEGMENT: u64 = (USER_CODE_SEGMENT_INDEX << 3) | (PrivilegeLevel::Ring3 as u64);

/// Initialize the GDT
///
/// # Safety
///
/// `unsafe` because the caller has to ensure it is only called once
/// and in a single-threaded context.
pub unsafe fn init(level_0_stack: VirtAddr) {
    #[cfg(debug_assertions)]
    eprintln!("init_gdt");

    #[inline(always)]
    #[allow(clippy::integer_arithmetic)]
    fn stack_end(stack_start: VirtAddr, num_pages: usize) -> VirtAddr {
        stack_start + num_pages * Page::size()
    }

    TSS.privilege_stack_table[0] = level_0_stack;

    // Assign the stacks for the exceptions and interrupts
    TSS.interrupt_stack_table
        .iter_mut()
        .zip(&STACKS)
        .for_each(|(p, v)| *p = stack_end(VirtAddr::from_ptr(v), STACK_NUM_PAGES));
    debug_assert_eq!(STACKS.len(), TSS.interrupt_stack_table.len());

    // `syscall` loads segments from STAR MSR assuming a data_segment follows `kernel_code_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let code_sel = GDT.add_entry(Descriptor::kernel_code_segment());

    use DescriptorFlags as Flags;
    let flags = Flags::USER_SEGMENT | Flags::PRESENT | Flags::WRITABLE;

    let data_sel = GDT.add_entry(Descriptor::UserSegment(flags.bits()));

    // `sysret` loads segments from STAR MSR assuming `user_code_segment` follows `user_data_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let user_data_sel = GDT.add_entry(Descriptor::user_data_segment());
    debug_assert_eq!(USER_DATA_SEGMENT, user_data_sel.0 as u64);

    let user_code_sel = GDT.add_entry(Descriptor::user_code_segment());
    debug_assert_eq!(USER_CODE_SEGMENT, user_code_sel.0 as u64);

    let tss_sel = GDT.add_entry(Descriptor::tss_segment(&TSS));

    GDT.load();

    // Setup the segment registers with the corresponding selectors
    set_cs(code_sel);
    load_ss(data_sel);
    load_tss(tss_sel);

    // Clear the other segment registers
    load_ss(SegmentSelector(0));
    load_ds(SegmentSelector(0));
    load_es(SegmentSelector(0));
    load_fs(SegmentSelector(0));
    load_gs(SegmentSelector(0));

    // Set the selectors to be set when userspace uses `syscall`
    Star::write(user_code_sel, user_data_sel, code_sel, data_sel).unwrap();

    // Set the pointer to the function to be called when userspace uses `syscall`
    LStar::write(VirtAddr::new(_syscall_enter as usize as u64));

    // Clear trap flag and interrupt enable
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::TRAP_FLAG);

    // Set the kernel gs base to the TSS to be used in `_syscall_enter`
    KernelGsBase::write(VirtAddr::new(&TSS as *const _ as u64));
}
