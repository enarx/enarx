// SPDX-License-Identifier: Apache-2.0

//! Debug functions

use core::mem::size_of;
use core::sync::atomic::Ordering;

use x86_64::instructions::tables::lidt;
use x86_64::structures::paging::Translate;
use x86_64::structures::DescriptorTablePointer;
use x86_64::VirtAddr;

use crate::addr::SHIM_VIRT_OFFSET;
use crate::paging::SHIM_PAGETABLE;
use crate::payload::PAYLOAD_VIRT_ADDR;
use crate::print;
use crate::snp::ghcb::{vmgexit_msr, GHCB_MSR_EXIT_REQ};
use crate::snp::snp_active;
use crate::PAYLOAD_READY;

/// Debug helper function for the early boot
///
/// # Safety
///
/// This function causes a triple fault!
#[inline(never)]
pub unsafe fn _early_debug_panic(reason: u64, value: u64) -> ! {
    let mut rbp: u64;

    // Safe the contents of the rbp register containing the stack frame pointer
    asm!("mov {}, rbp", out(reg) rbp);

    if snp_active() {
        _load_invalid_idt();

        vmgexit_msr(
            GHCB_MSR_EXIT_REQ,
            value.wrapping_shl(16) | (reason & 0x7).wrapping_shl(12),
            0,
        );
        // a GHCB_MSR_EXIT_REQ should not return, but in case it does the
        // `unreachable` `ud2` will cause a triple fault.
        unreachable!();
    }

    let mut frames = backtrace(rbp);

    frames[11] = reason;
    frames[12] = value;

    _inline_ud2_triple_fault(frames)
}

/// Provoke a triple fault to shutdown the machine
///
/// An illegal IDT is loaded with limit=0 and an #UD is produced
///
/// Fun read: http://www.rcollins.org/Productivity/TripleFault.html
///
/// # Safety
///
/// This function causes a triple fault!
#[inline(never)]
pub unsafe fn _enarx_asm_triple_fault() -> ! {
    let mut rbp: u64;

    // Safe the contents of the rbp register containing the stack frame pointer
    asm!("mov {}, rbp", out(reg) rbp);

    if snp_active() {
        _early_debug_panic(0x7, 0xFF);
    }

    let frames = backtrace(rbp);

    _inline_ud2_triple_fault(frames)
}

/// Load an invalid DescriptorTablePointer with no base and limit and
/// provoke an #UD, which will lead to a triple fault
#[inline(always)]
unsafe fn _inline_ud2_triple_fault(frames: [u64; 16]) -> ! {
    _load_invalid_idt();

    // ud2 with defined register contents
    asm!(
        "ud2",

        in("rax") frames[0],
        in("rcx") frames[1],
        in("rdx") frames[2],
        in("rsi") frames[3],
        in("rdi") frames[4],
        in("r8") frames[5],
        in("r9") frames[6],
        in("r10") frames[7],
        in("r11") frames[8],
        in("r12") frames[9],
        in("r13") frames[10],
        in("r14") frames[11],
        in("r15") frames[12],

        options(nomem, nostack, noreturn)
    )
}

/// Load an invalid DescriptorTablePointer with no base and limit
#[inline(always)]
unsafe fn _load_invalid_idt() {
    let dtp = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::new(0),
    };

    // Load the invalid IDT
    lidt(&dtp);
}

/// Produce a backtrace from a frame pointer
#[inline(always)]
unsafe fn backtrace(mut rbp: u64) -> [u64; 16] {
    let mut frames = [0u64; 16];

    for ele in frames.iter_mut() {
        if let Some(rip_rbp) = rbp.checked_add(size_of::<usize>() as _) {
            if rip_rbp < SHIM_VIRT_OFFSET {
                break;
            }
            let rip = *(rip_rbp as *const u64);
            if let Some(rip) = rip
                .checked_sub(SHIM_VIRT_OFFSET)
                .and_then(|v| v.checked_sub(1))
            {
                *ele = rip;
                rbp = *(rbp as *const u64);
            } else {
                // Not a shim virtual address
                break;
            }
        } else {
            // RBP OVERFLOW
            break;
        }
    }
    frames
}

#[inline(never)]
/// print a stack trace from a stack frame pointer
pub fn print_stack_trace() {
    let mut rbp: usize;

    unsafe {
        asm!("mov {}, rbp", out(reg) rbp);
        stack_trace_from_rbp(rbp);
    }
}

unsafe fn stack_trace_from_rbp(mut rbp: usize) {
    print::_eprint(format_args!("TRACE:\n"));

    if SHIM_PAGETABLE.try_read().is_none() {
        SHIM_PAGETABLE.force_unlock_write()
    }

    let shim_offset = crate::addr::SHIM_VIRT_OFFSET as usize;

    let active_table = SHIM_PAGETABLE.read();

    //Maximum 64 frames
    for _frame in 0..64 {
        if rbp == 0
            || VirtAddr::try_new(rbp as _).is_err()
            || active_table
                .translate_addr(VirtAddr::new(rbp as _))
                .is_none()
        {
            break;
        }

        if let Some(rip_rbp) = rbp.checked_add(size_of::<usize>() as _) {
            if active_table
                .translate_addr(VirtAddr::new(rip_rbp as _))
                .is_none()
            {
                break;
            }

            let rip = *(rip_rbp as *const usize);
            if let Some(rip) = rip.checked_sub(1) {
                if rip == 0 {
                    break;
                }

                if let Some(rip) = rip.checked_sub(shim_offset) {
                    print::_eprint(format_args!("S 0x{:>016x}\n", rip));
                    rbp = *(rbp as *const usize);
                } else if PAYLOAD_READY.load(Ordering::Relaxed) {
                    if let Some(rip) = rip.checked_sub(PAYLOAD_VIRT_ADDR.read().as_u64() as _) {
                        print::_eprint(format_args!("P 0x{:>016x}\n", rip));
                        rbp = *(rbp as *const usize);
                    } else {
                        break;
                    }
                }
            } else {
                // RIP zero
                break;
            }
        } else {
            // RBP OVERFLOW
            break;
        }
    }
}
