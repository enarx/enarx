// SPDX-License-Identifier: Apache-2.0

//! Functions needing `asm!` blocks

use crate::addr::SHIM_VIRT_OFFSET;
use crate::hostlib::MAX_SETUP_SIZE;
use core::mem::size_of;
use x86_64::instructions::tables::lidt;
use x86_64::structures::DescriptorTablePointer;
use x86_64::VirtAddr;

#[allow(clippy::integer_arithmetic)]
const SHIM_OFFSET: u64 = 1u64 + SHIM_VIRT_OFFSET + MAX_SETUP_SIZE as u64;

/// Debug helper function for the early boot
///
/// # Safety
///
/// This function causes a triple fault!
#[inline(never)]
pub unsafe fn _enarx_asm_triple_debug(value: u64) -> ! {
    // Create an invalid DescriptorTablePointer with no base and limit
    let dtp = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::new(0),
    };
    // Load the invalid IDT
    lidt(&dtp);

    // Provoke an #UD, which will lead to a triple fault, because of the invalid IDT
    asm!("ud2",
        in("rax") value, // the first two frames are from panic
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

    let mut frames = [0u64; 16];

    asm!("mov {}, rbp", out(reg) rbp);

    // Create an invalid DescriptorTablePointer with no base and limit
    let dtp = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::new(0),
    };
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
    in("rcx") frames[3],
    in("rdx") frames[4],
    in("rsi") frames[5],
    in("rdi") frames[6],
    in("r8") frames[7],
    in("r9") frames[8],
    in("r10") frames[9],
    in("r11") frames[10],
    in("r12") frames[11],
    in("r13") frames[12],
    in("r14") frames[13],
    in("r15") frames[14],
        options(nomem, nostack)
    );

    // Extra hlt loop, in case hell freezes
    loop {
        x86_64::instructions::hlt()
    }
}
