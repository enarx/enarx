// SPDX-License-Identifier: Apache-2.0

//! Functions needing `asm!` blocks

/// Provoke a triple fault to shutdown the machine
///
/// An illegal IDT is loaded with limit=0 and an #UD is produced
///
/// Fun read: http://www.rcollins.org/Productivity/TripleFault.html
///
/// # Safety
///
/// This function causes a triple fault!
pub unsafe fn _enarx_asm_triple_fault() -> ! {
    use x86_64::instructions::tables::lidt;
    use x86_64::structures::DescriptorTablePointer;
    // Create an invalid DescriptorTablePointer with no base and limit
    let dtp = DescriptorTablePointer { limit: 0, base: 0 };
    // Load the invalid IDT
    lidt(&dtp);
    // Provoke an #UD, which will lead to a triple fault, because of the invalid IDT
    asm!("ud2", options(nomem, nostack));
    // Extra hlt loop, in case hell freezes
    loop {
        x86_64::instructions::hlt()
    }
}
