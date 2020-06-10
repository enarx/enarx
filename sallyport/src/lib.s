# SPDX-License-Identifier: Apache-2.0

    .text
    .globl sallyport_syscall
    .type sallyport_syscall, @function
sallyport_syscall:
    push    %rsi

    mov     0x00(%rdi),     %rax
    mov     0x30(%rdi),     %r9
    mov     0x28(%rdi),     %r8
    mov     0x20(%rdi),     %r10
    mov     0x18(%rdi),     %rdx
    mov     0x10(%rdi),     %rsi
    mov     0x08(%rdi),     %rdi

    syscall
    pop     %rsi

    mov     %rax,           0x00(%rsi)
    mov     %rdx,           0x08(%rsi)
    movq    $0,             0x10(%rsi)
    ret
