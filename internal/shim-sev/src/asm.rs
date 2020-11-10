// SPDX-License-Identifier: Apache-2.0

//! Functions needing `asm!` blocks

use crate::addr::SHIM_VIRT_OFFSET;
use crate::hostlib::ALIGN_ABOVE_2MB;
use core::mem::size_of;
use x86_64::instructions::tables::lidt;
use x86_64::structures::DescriptorTablePointer;

#[allow(clippy::integer_arithmetic)]
const SHIM_OFFSET: u64 = 1u64 + SHIM_VIRT_OFFSET + ALIGN_ABOVE_2MB as u64;

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

    let mut frames = [0u64; 16];

    asm!("mov {}, rbp", out(reg) rbp);

    // Create an invalid DescriptorTablePointer with no base and limit
    let dtp = DescriptorTablePointer { limit: 0, base: 0 };
    // Load the invalid IDT
    lidt(&dtp);

    for ele in frames.iter_mut() {
        if let Some(rip_rbp) = rbp.checked_add(size_of::<usize>() as _) {
            let rip = *(rip_rbp as *const u64);
            if let Some(rip) = rip.checked_sub(SHIM_OFFSET) {
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

    // Provoke an #UD, which will lead to a triple fault, because of the invalid IDT
    asm!("ud2",
    in("rax") frames[2], // the first two frames are from panic
    in("rbx") frames[3],
    in("rcx") frames[4],
    in("rdx") frames[5],
    in("rsi") frames[6],
    in("rdi") frames[7],
    in("r8") frames[8],
    in("r9") frames[9],
    in("r10") frames[10],
    in("r11") frames[11],
    in("r12") frames[12],
    in("r13") frames[13],
    in("r14") frames[14],
    in("r15") frames[15],
        options(nomem, nostack)
    );

    // Extra hlt loop, in case hell freezes
    loop {
        x86_64::instructions::hlt()
    }
}
