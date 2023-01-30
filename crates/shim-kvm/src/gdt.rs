// SPDX-License-Identifier: Apache-2.0

//! Global Descriptor Table init

use crate::hostcall::BlockGuard;
use crate::syscall::_syscall_enter;
use crate::thread::TcbRefCell;
use crate::MAX_NUM_CPUS;

use alloc::boxed::Box;

use x86_64::instructions::segmentation::{Segment, Segment64, CS, DS, ES, FS, GS, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::model_specific::{KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// Initialize the GDT
///
/// # Safety
/// The caller has to ensure that the stack pointer is valid and 16 byte aligned.
/// The caller has to ensure that the CPU number is valid.
/// The caller has to ensure that this function is only called once per CPU.
#[cfg_attr(coverage, no_coverage)]
pub unsafe fn init(cpunum: usize, stack_pointer: VirtAddr) {
    assert!(cpunum < MAX_NUM_CPUS);

    eprintln!("[{cpunum}] init_gdt");

    let gdt = Box::leak(Box::new(GlobalDescriptorTable::new()));

    // `syscall` loads segments from STAR MSR assuming a data_segment follows `kernel_code_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let code = gdt.add_entry(Descriptor::kernel_code_segment());
    let data = gdt.add_entry(Descriptor::kernel_data_segment());

    // `sysret` loads segments from STAR MSR assuming `user_code_segment` follows `user_data_segment`
    // so the ordering is crucial here. Star::write() will panic otherwise later.
    let user_data = gdt.add_entry(Descriptor::user_data_segment());
    let user_code = gdt.add_entry(Descriptor::user_code_segment());

    let mut tss = Box::new(TaskStateSegment::new());
    tss.privilege_stack_table[0] = stack_pointer;
    let tss = Box::leak(tss);
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

    // SAFETY: only called once per CPU
    let block = unsafe { BlockGuard::new(cpunum) };

    // Set the kernel gs base to the Tcb to be used in `_syscall_enter`
    let tcb = Box::new(TcbRefCell::new(stack_pointer, block));
    let base = VirtAddr::from_ptr(Box::leak(tcb));
    KernelGsBase::write(base);

    // Safety: the GS base is not yet in use, because no syscalls happened yet for this CPU
    unsafe { GS::write_base(base) };

    eprintln!("[{cpunum}] init_gdt done");
}
