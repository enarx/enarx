# SPDX-License-Identifier: Apache-2.0

.section .text, "ax"
.code64

XSAVE_STACK_OFFSET = (16*64)

.macro ISR num has_error:req
    .p2align 4
.type _isr_\num, @function
.global _isr_\num
_isr_\num:
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %rax
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11
    pushq   %rbx

    movq    %rsp, %rbx
    movq    80(%rsp), %rsi

    # rsp is first argument
    movq    %rsp, %rdi
    subq   $(XSAVE_STACK_OFFSET), %rsp

    # add xsave area and align stack
.if \has_error
    addq    $(11*8), %rdi
.else
    addq    $(10*8), %rdi
.endif

    # align stack
    andq   $(~(0x40-1)), %rsp

    # xsave
    # memzero xsave array
    xorq    %rax, %rax
1:
    movq    $0, (%rsp,%rax,8)
    addl    $1, %eax
    cmpl    $(XSAVE_STACK_OFFSET/8), %eax
    jne     1b

    movl   $-1, %edx
    movl   $-1, %eax
    xsaveopt  (%rsp)
    # xsave end

    movq   $\num, %rdx

    callq  run_interrupt_fn

    # xrstor
    movl   $-1, %edx
    movl   $-1, %eax
    xrstor (%rsp)

    # xrstor end
    movq    %rbx, %rsp

    popq    %rbx
    popq    %r11
    popq    %r10
    popq    %r9
    popq    %r8
    popq    %rax
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %rdi

    iretq
    .p2align 4
.endm

ISR 0 has_error=0
ISR 1 has_error=0
ISR 2 has_error=0
ISR 3 has_error=0
ISR 4 has_error=0
ISR 5 has_error=0
ISR 6 has_error=0
ISR 7 has_error=0
ISR 8 has_error=1
#ISR 9
ISR 10 has_error=1
ISR 11 has_error=1
ISR 12 has_error=1
ISR 13 has_error=1
ISR 14 has_error=1
#ISR 15
ISR 16 has_error=0
ISR 17 has_error=1
ISR 18 has_error=0
ISR 19 has_error=0
ISR 20 has_error=0
# 21..=29
ISR 30 has_error=1

#ISR 32 has_error=0
#ISR 33 has_error=0

#ISR 100 has_error=0
#ISR 101 has_error=0
#ISR 102 has_error=0
