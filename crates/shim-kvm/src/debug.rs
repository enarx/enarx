// SPDX-License-Identifier: Apache-2.0

//! Debug functions

use core::arch::asm;

use x86_64::instructions::tables::lidt;
use x86_64::structures::DescriptorTablePointer;
use x86_64::VirtAddr;

#[cfg(all(feature = "dbg", not(test)))]
use crate::addr::SHIM_VIRT_OFFSET;
use crate::snp::ghcb::{vmgexit_msr, GhcbMsr};
use crate::snp::snp_active;

/// Debug helper function for the early boot
///
/// # Safety
///
/// This function causes a triple fault!
#[inline(never)]
#[cfg_attr(coverage, no_coverage)]
pub unsafe fn _early_debug_panic(reason: u64, value: u64) -> ! {
    if cfg!(all(feature = "dbg", not(test))) {
        let mut rbp: u64;

        // Safe the contents of the rbp register containing the stack frame pointer
        asm!("mov {}, rbp", out(reg) rbp);

        if snp_active() {
            _load_invalid_idt();

            vmgexit_msr(
                GhcbMsr::EXIT_REQ,
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
    } else {
        _load_invalid_idt();
        // `unreachable` `ud2` will cause a triple fault.
        unreachable!();
    }
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
#[cfg_attr(coverage, no_coverage)]
pub unsafe fn _enarx_asm_triple_fault() -> ! {
    if cfg!(all(feature = "dbg", not(test))) {
        let mut rbp: u64;

        // Safe the contents of the rbp register containing the stack frame pointer
        asm!("mov {}, rbp", out(reg) rbp);

        if snp_active() {
            _early_debug_panic(0x7, 0xFF);
        }

        let frames = backtrace(rbp);

        _inline_ud2_triple_fault(frames)
    } else {
        _load_invalid_idt();
        // `unreachable` `ud2` will cause a triple fault.
        unreachable!();
    }
}

/// Load an invalid DescriptorTablePointer with no base and limit and
/// provoke an #UD, which will lead to a triple fault
#[inline(always)]
#[cfg_attr(coverage, no_coverage)]
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
#[cfg_attr(coverage, no_coverage)]
unsafe fn _load_invalid_idt() {
    let dtp = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::new(0),
    };

    // Load the invalid IDT
    lidt(&dtp);
}

#[cfg(not(all(feature = "dbg", not(test))))]
unsafe fn backtrace(_rbp: u64) -> [u64; 16] {
    [0u64; 16]
}

#[cfg(all(feature = "dbg", not(test)))]
/// Produce a backtrace from a frame pointer
#[inline(always)]
#[cfg_attr(coverage, no_coverage)]
unsafe fn backtrace(mut rbp: u64) -> [u64; 16] {
    use core::mem::size_of;

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

#[cfg(all(feature = "dbg", not(test)))]
#[inline(never)]
/// print a stack trace from a stack frame pointer
#[cfg_attr(coverage, no_coverage)]
pub fn print_stack_trace() {
    let mut rbp: usize;

    unsafe {
        asm!("mov {}, rbp", out(reg) rbp);
        stack_trace_from_rbp(rbp);
    }
}

#[cfg(all(feature = "dbg", not(test)))]
#[cfg_attr(coverage, no_coverage)]
unsafe fn stack_trace_from_rbp(mut rbp: usize) {
    use crate::exec::EXEC_VIRT_ADDR;
    use crate::paging::SHIM_PAGETABLE;
    use crate::stdio::_eprint;

    use core::mem::size_of;
    use core::sync::atomic::Ordering;

    use x86_64::structures::paging::Translate;

    _eprint(format_args!("TRACE:\n"));

    if SHIM_PAGETABLE.try_read().is_none() {
        SHIM_PAGETABLE.force_write_unlock()
    }

    let shim_offset = SHIM_VIRT_OFFSET as usize;

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
                    _eprint(format_args!("S 0x{rip:>016x}\n"));
                    rbp = *(rbp as *const usize);
                } else if crate::exec::EXEC_READY.load(Ordering::Relaxed) {
                    if let Some(rip) = rip.checked_sub(EXEC_VIRT_ADDR.read().as_u64() as _) {
                        _eprint(format_args!("E 0x{rip:>016x}\n"));
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

#[cfg(all(feature = "dbg", not(test)))]
#[cfg_attr(coverage, no_coverage)]
pub(crate) fn interrupt_trace(stack_frame: &crate::interrupts::ExtendedInterruptStackFrame) {
    use crate::exec::EXEC_VIRT_ADDR;

    let exec_virt = *EXEC_VIRT_ADDR.read();
    let mut addr = stack_frame.instruction_pointer;

    if addr.as_u64() > SHIM_VIRT_OFFSET {
        addr -= SHIM_VIRT_OFFSET;
        eprintln!("TRACE:\nS 0x{:>016x}", addr.as_u64());
    } else if addr > exec_virt {
        addr -= exec_virt.as_u64();
        eprintln!("TRACE:\nE 0x{:>016x}", addr.as_u64());
    };

    unsafe {
        stack_trace_from_rbp(stack_frame.rbp as _);
    }

    print_stack_trace();
}
