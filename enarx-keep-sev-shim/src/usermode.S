# SPDX-License-Identifier: Apache-2.0

// (gdt::USER_DATA_SEGMENT_INDEX << 3) | PRIVILEGE_LEVEL
#define USER_DATA_SEGMENT ((3 << 3) | 3)

//(gdt::USER_CODE_SEGMENT_INDEX << 3) | PRIVILEGE_LEVEL
#define USER_CODE_SEGMENT ((4 << 3) | 3)

.section .text, "ax"
.global usermode
.type usermode, @function
.code64

.p2align 4
usermode:
    # %rdi: instruction pointer
    # %rsi: stack pointer
    # %rdx: argument

    # prepare the stack for iretq
    pushq    $USER_DATA_SEGMENT
    pushq    %rsi                                   # stack pointer
    pushq    $(1 << 9)                              # RFlags - set interrupt enable flag
    pushq    $USER_CODE_SEGMENT
    pushq    %rdi                                   # instruction pointer

    # clear all registers
    xorq     %rax,                  %rax
    xorq     %rbx,                  %rbx
    xorq     %rcx,                  %rcx
    xorq     %rdx,                  %rdx
    xorq     %rsi,                  %rsi
    xorq     %rdi,                  %rdi
    xorq     %rbp,                  %rbp
    xorq     %r8,                   %r8
    xorq     %r9,                   %r9
    xorq     %r10,                  %r10
    xorq     %r11,                  %r11
    xorq     %r12,                  %r12
    xorq     %r13,                  %r13
    xorq     %r14,                  %r14
    xorq     %r15,                  %r15

    # clear all segment selectors
    movq     %r11,                  %ds
    movq     %r11,                  %es
    movq     %r11,                  %fs
    movq     %r11,                  %gs

    # clear the FPU
    fninit

    # do a simulated return from interrupt
    # this sets the segments and rip from the stack
    iretq
