// SPDX-License-Identifier: Apache-2.0

//! switch to Ring 3 aka usermode

use core::arch::asm;

use const_default::ConstDefault;

/// Enter Ring 3
///
/// # Safety
///
/// Because the caller can give any `entry_point` and `stack_pointer`
/// including 0, this function is unsafe.
pub unsafe fn usermode(ip: u64, sp: u64) -> ! {
    static XSAVE: xsave::XSave = <xsave::XSave as ConstDefault>::DEFAULT;

    // switch to ring3 with the stack setup and registers cleared
    asm!(
        // IP is in rcx, required by sysret

        "pushfq",                   // Copy RFLAGS into r11, required by sysret
        "pop    r11",

        // Load userspace stack
        "mov    rsp,    {SP}",

        "mov    rdx,    ~0",        // Set mask for xrstor in rdx
        "mov    rax,    ~0",        // Set mask for xrstor in rax
        "xrstor [rip + {XSAVE}]",   // Clear xCPU state with synthetic state

        "xor    rax,    rax",
        "xor    rbx,    rbx",
        "xor    rdx,    rdx",
        "xor    rsi,    rsi",
        "xor    rdi,    rdi",
        "xor    rbp,    rbp",
        "xor    r8,     r8",
        "xor    r9,     r9",
        "xor    r10,    r10",
        "xor    r12,    r12",
        "xor    r13,    r13",
        "xor    r14,    r14",
        "xor    r15,    r15",

        // clear all segment selectors
        "mov    ds,     r10",
        "mov    es,     r10",
        "mov    fs,     r10",

        "swapgs",
        // swapgs variant of Spectre V1. Disable speculation past this point
        "lfence",

        "sysretq",

        XSAVE = sym XSAVE,

        SP = in(reg) sp,
        in("rcx") ip,

        options(noreturn)
    )
}
