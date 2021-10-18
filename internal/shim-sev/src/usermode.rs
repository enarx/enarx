// SPDX-License-Identifier: Apache-2.0

//! switch to Ring 3 aka usermode

use crate::gdt::{USER_CODE_SEGMENT, USER_DATA_SEGMENT};

use x86_64::registers::rflags::RFlags;

/// Enter Ring 3
///
/// # Safety
///
/// Because the caller can give any `entry_point` and `stack_pointer`
/// including 0, this function is unsafe.
pub unsafe fn usermode(ip: u64, sp: u64) -> ! {
    // switch to ring3 with the stack setup
    // and registers cleared
    asm!(
        "push     {USER_DATA_SEGMENT}",
        "push     {SP}",
        "push     {RFLAGS}",
        "push     {USER_CODE_SEGMENT}",
        "push     {IP}",
        "xor      rax, rax",
        "xor      rbx, rbx",
        "xor      rcx, rcx",
        "xor      rdx, rdx",
        "xor      rsi, rsi",
        "xor      rdi, rdi",
        "xor      rbp, rbp",
        "xor      r8,  r8",
        "xor      r9,  r9",
        "xor      r10, r10",
        "xor      r11, r11",
        "xor      r12, r12",
        "xor      r13, r13",
        "xor      r14, r14",
        "xor      r15, r15",

        // clear all segment selectors
        "mov      ds,  r11",
        "mov      es,  r11",
        "mov      fs,  r11",
        "mov      gs,  r11",

        // clear the FPU
        "fninit",

        // do a simulated return from interrupt
        // this sets the segments and rip from the stack
        "iretq",

        USER_DATA_SEGMENT = const USER_DATA_SEGMENT,
        SP = in(reg) sp,
        RFLAGS = const RFlags::INTERRUPT_FLAG.bits(),
        USER_CODE_SEGMENT = const USER_CODE_SEGMENT,
        IP = in(reg) ip,

        options(noreturn, nomem)
    )
}
