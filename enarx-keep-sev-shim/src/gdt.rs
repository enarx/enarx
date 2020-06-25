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

static mut TSS: Option<TaskStateSegment> = None;
pub(crate) static mut GDT: Option<(GlobalDescriptorTable, Selectors)> = None;

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

const STACK_NUM_PAGES: usize = 5;

/// The selectors used for the GDT
pub struct Selectors {
    /// The code selector of the shim
    pub code_selector: SegmentSelector,
    /// The data selector of the shim
    pub data_selector: SegmentSelector,
    /// The data selector of the payload
    pub user_data_selector: SegmentSelector,
    /// The code selector of the payload
    pub user_code_selector: SegmentSelector,
    /// The tss selector
    pub tss_selector: SegmentSelector,
}

/// Initialize the GDT
pub fn init() {
    #[cfg(debug_assertions)]
    eprintln!("init_gdt");

    #[inline(always)]
    #[allow(clippy::integer_arithmetic)]
    fn stack_end(stack_start: VirtAddr, num_pages: usize) -> VirtAddr {
        stack_start + num_pages * Page::size()
    }

    unsafe {
        TSS = Some({
            let mut tss = TaskStateSegment::new();

            static mut STACKS: [[Page; STACK_NUM_PAGES]; 8] =
                [[Page::zeroed(); STACK_NUM_PAGES]; 8];

            // The stack for RING 0
            tss.privilege_stack_table[0] =
                stack_end(VirtAddr::from_ptr(&STACKS[0]), STACK_NUM_PAGES);

            // The stacks for the exceptions and interrupts
            for i in 0..7 {
                tss.interrupt_stack_table[i] =
                    stack_end(VirtAddr::from_ptr(&STACKS[i + 1]), STACK_NUM_PAGES);
            }
            tss
        });
    }

    unsafe {
        GDT = Some({
            use DescriptorFlags as Flags;

            let mut gdt = GlobalDescriptorTable::new();

            // `syscall` loads segments from STAR MSR assuming a data_segment follows `kernel_code_segment`
            // so the ordering is crucial here. Star::write() will panic otherwise later.
            let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
            let flags = Flags::USER_SEGMENT | Flags::PRESENT | Flags::WRITABLE;
            let data_selector = gdt.add_entry(Descriptor::UserSegment(flags.bits()));

            // `sysret` loads segments from STAR MSR assuming `user_code_segment` follows `user_data_segment`
            // so the ordering is crucial here. Star::write() will panic otherwise later.
            let user_data_selector = gdt.add_entry(Descriptor::user_data_segment());
            debug_assert_eq!(USER_DATA_SEGMENT, user_data_selector.0 as u64);

            let user_code_selector = gdt.add_entry(Descriptor::user_code_segment());
            debug_assert_eq!(USER_CODE_SEGMENT, user_code_selector.0 as u64);

            let tss_selector = gdt.add_entry(Descriptor::tss_segment(TSS.as_ref().unwrap()));
            (
                gdt,
                Selectors {
                    code_selector,
                    data_selector,
                    user_data_selector,
                    user_code_selector,
                    tss_selector,
                },
            )
        });
    }

    let gdt = unsafe { GDT.as_ref().unwrap() };

    gdt.0.load();

    unsafe {
        // Setup the segment registers with the corresponding selectors
        set_cs(gdt.1.code_selector);
        load_ss(gdt.1.data_selector);
        load_tss(gdt.1.tss_selector);

        // Clear the other segment registers
        load_ss(SegmentSelector(0));
        load_ds(SegmentSelector(0));
        load_es(SegmentSelector(0));
        load_fs(SegmentSelector(0));
        load_gs(SegmentSelector(0));

        // Set the selectors to be set when userspace uses `syscall`
        Star::write(
            gdt.1.user_code_selector,
            gdt.1.user_data_selector,
            gdt.1.code_selector,
            gdt.1.data_selector,
        )
        .unwrap();

        // Set the pointer to the function to be called when userspace uses `syscall`
        LStar::write(VirtAddr::new(_syscall_enter as usize as u64));

        // Clear trap flag and interrupt enable
        SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::TRAP_FLAG);

        // Set the kernel gs base to the TSS to be used in `_syscall_enter`
        KernelGsBase::write(VirtAddr::new(TSS.as_ref().unwrap() as *const _ as u64));
    }
}
