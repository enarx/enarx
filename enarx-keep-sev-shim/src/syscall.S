# SPDX-License-Identifier: Apache-2.0

// (gdt::USER_DATA_SEGMENT_INDEX << 3) | PRIVILEGE_LEVEL
#define USER_DATA_SEGMENT ((3 << 3) | 3)

//(gdt::USER_CODE_SEGMENT_INDEX << 3) | PRIVILEGE_LEVEL
#define USER_CODE_SEGMENT ((4 << 3) | 3)

/*
# TSS:
# reserved_1: u32
# stack_pointer_ring_0 : u64
# stack_pointer_ring_1 : u64
# stack_pointer_ring_2 : u64
# stack_pointer_ring_3 : u64
# ...
*/
#define KERNEL_RSP_OFF 4
#define USR_RSP_OFF (KERNEL_RSP_OFF + 3*8)

.section .text, "ax"
.global _syscall_enter
.type _syscall_enter, @function
.code64

.p2align 4
_syscall_enter:
    # prepare the stack for iretq and load the kernel rsp
    swapgs                                          # set gs segment to TSS
    movq   %rsp,                    %gs:0x1c        # save userspace rsp
    movq   %gs:KERNEL_RSP_OFF,      %rsp            # load kernel rsp
    pushq  $USER_DATA_SEGMENT
    pushq  %gs:USR_RSP_OFF                          # push userspace rsp - stack_pointer_ring_3
    movq   $0x0,                    %gs:USR_RSP_OFF # clear userspace rsp in the TSS
    pushq  %r11                                     # push RFLAGS stored in r11
    pushq  $USER_CODE_SEGMENT
    pushq  %rcx                                     # push userspace return pointer
    swapgs                                          # restore gs

    # Arguments in registers:
    # SYSV:    rdi, rsi, rdx, rcx, r8, r9
    # SYSCALL: rdi, rsi, rdx, r10, r8, r9 and syscall number in rax
    movq    %r10,                    %rcx

    # save registers
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %r10
    pushq   %r8
    pushq   %r9

    # syscall number on the stack as the seventh argument
    pushq   %rax

    callq  syscall_rust

    # skip %rax pop, as it is the return value
    addq    $8,                     %rsp

    # restore registers
    popq    %r9
    popq    %r8
    popq    %r10
    popq    %rdx
    popq    %rsi
    popq    %rdi

    iretq
