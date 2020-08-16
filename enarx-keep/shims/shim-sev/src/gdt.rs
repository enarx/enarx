// SPDX-License-Identifier: Apache-2.0

//! Global Descriptor Table init

use crate::shim_stack::init_shim_stack;
use crate::syscall::_syscall_enter;
use core::ops::Deref;
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

lazy_static! {
    /// The global TSS
    pub static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();

        #[inline(always)]
        #[allow(clippy::integer_arithmetic)]
        fn stack_end(stack_start: VirtAddr, num_pages: usize) -> VirtAddr {
            stack_start + num_pages * Page::size()
        }

        tss.privilege_stack_table[0] = init_shim_stack();

        // Assign the stacks for the exceptions and interrupts
        unsafe {
            tss.interrupt_stack_table
                .iter_mut()
                .zip(&STACKS)
                .for_each(|(p, v)| *p = stack_end(VirtAddr::from_ptr(v), STACK_NUM_PAGES));

            debug_assert_eq!(STACKS.len(), tss.interrupt_stack_table.len());
        }

        tss
    };
}

/// The Selectors used in the GDT setup
pub struct Selectors {
    /// shim code selector
    pub code: SegmentSelector,
    /// shim data selector
    pub data: SegmentSelector,
    /// payload data selector
    pub user_data: SegmentSelector,
    /// payload code selector
    pub user_code: SegmentSelector,
    /// TSS selector
    pub tss: SegmentSelector,
}

lazy_static! {
    /// The global GDT
    pub static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();

        // `syscall` loads segments from STAR MSR assuming a data_segment follows `kernel_code_segment`
        // so the ordering is crucial here. Star::write() will panic otherwise later.
        let code = gdt.add_entry(Descriptor::kernel_code_segment());

        use DescriptorFlags as Flags;
        let flags = Flags::USER_SEGMENT | Flags::PRESENT | Flags::WRITABLE;

        let data = gdt.add_entry(Descriptor::UserSegment(flags.bits()));

        // `sysret` loads segments from STAR MSR assuming `user_code_segment` follows `user_data_segment`
        // so the ordering is crucial here. Star::write() will panic otherwise later.
        let user_data = gdt.add_entry(Descriptor::user_data_segment());
        debug_assert_eq!(USER_DATA_SEGMENT, user_data.0 as u64);

        let user_code = gdt.add_entry(Descriptor::user_code_segment());
        debug_assert_eq!(USER_CODE_SEGMENT, user_code.0 as u64);

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
    };
}

/// The user data segment
///
/// For performance and simplicity reasons, this is a constant
/// in the assembler code and here for debug_assert!()
const USER_DATA_SEGMENT_INDEX: u64 = 3;
/// The User Data Segment as a constant to be used in asm!() blocks
pub const USER_DATA_SEGMENT: u64 = (USER_DATA_SEGMENT_INDEX << 3) | (PrivilegeLevel::Ring3 as u64);

/// The user code segment
///
/// For performance and simplicity reasons, this is a constant
/// in the assembler code and here for debug_assert!()
const USER_CODE_SEGMENT_INDEX: u64 = 4;
/// The User Code Segment as a constant to be used in asm!() blocks
pub const USER_CODE_SEGMENT: u64 = (USER_CODE_SEGMENT_INDEX << 3) | (PrivilegeLevel::Ring3 as u64);

/// Initialize the GDT
///
/// # Safety
///
/// `unsafe` because the caller has to ensure it is only called once
/// and in a single-threaded context.
pub unsafe fn init() {
    #[cfg(debug_assertions)]
    crate::eprintln!("init_gdt");

    GDT.0.load();

    // Setup the segment registers with the corresponding selectors
    set_cs(GDT.1.code);
    load_ss(GDT.1.data);
    load_tss(GDT.1.tss);

    // Clear the other segment registers
    load_ss(SegmentSelector(0));
    load_ds(SegmentSelector(0));
    load_es(SegmentSelector(0));
    load_fs(SegmentSelector(0));
    load_gs(SegmentSelector(0));

    // Set the selectors to be set when userspace uses `syscall`
    Star::write(GDT.1.user_code, GDT.1.user_data, GDT.1.code, GDT.1.data).unwrap();

    // Set the pointer to the function to be called when userspace uses `syscall`
    LStar::write(VirtAddr::new(_syscall_enter as usize as u64));

    // Clear trap flag and interrupt enable
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::TRAP_FLAG);

    // Set the kernel gs base to the TSS to be used in `_syscall_enter`
    // Important: TSS.deref() != &TSS because of lazy_static
    KernelGsBase::write(VirtAddr::new(TSS.deref() as *const _ as u64));
}
