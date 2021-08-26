// SPDX-License-Identifier: Apache-2.0

//! Functions needing `asm!` blocks

use crate::addr::SHIM_VIRT_OFFSET;
use core::mem::size_of;
use x86_64::instructions::tables::lidt;
use x86_64::structures::DescriptorTablePointer;
use x86_64::VirtAddr;

/// Debug helper function for the early boot
///
/// # Safety
///
/// This function causes a triple fault!
#[inline(never)]
pub unsafe fn _early_debug_panic(reason: u64, value: u64) -> ! {
    let mut rbp: u64;

    asm!("mov {}, rbp", out(reg) rbp);

    load_invalid_idt();

    let frames = backtrace(rbp);

    // Provoke an #UD, which will lead to a triple fault, because of the invalid IDT
    asm!("ud2",
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
    in("r14") reason,
    in("r15") value,
    options(nomem, nostack)
    );

    // Extra hlt loop, in case hell freezes
    loop {
        x86_64::instructions::hlt()
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
pub unsafe fn _enarx_asm_triple_fault() -> ! {
    let mut rbp: u64;

    asm!("mov {}, rbp", out(reg) rbp);

    let frames = backtrace(rbp);

    load_invalid_idt();

    // Provoke an #UD, which will lead to a triple fault, because of the invalid IDT
    asm!("ud2",
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
        options(nomem, nostack)
    );

    // Extra hlt loop, in case hell freezes
    loop {
        x86_64::instructions::hlt()
    }
}

/// Load an invalid DescriptorTablePointer with no base and limit
#[inline(always)]
unsafe fn load_invalid_idt() {
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
