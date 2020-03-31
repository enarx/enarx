# SPDX-License-Identifier: Apache-2.0

.section .text, "ax"
.global _usermode
.type _usermode, @function
.code64

.p2align 4
_usermode:
    movq    $0x1b,%r10     # ((gdt::USER_DATA_SEG << 3) | 3), # Data segment
    movq    %rsi,%r11      # stack pointer
#    movq    $0x200,%r12    # (1 << 9), # Flags - Set interrupt enable flag
# FIXME: Double fault after iretq in qemu .. some interrupt is happening
    movq    $0x000,%r12    # (1 << 9), # Flags - Set interrupt enable flag
    movq    $0x23,%r13     # ((gdt::USER_CODE_SEG << 3) | 3), # Code segment
    movq    %rdi,%r14      # IP entry_point
    movq    %rdx,%r15      # arg
    push    %r10
    push    %r11
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    xorq    %rax,%rax
    xorq    %rdx,%rdx
    xorq    %rbx,%rbx
    xorq    %rcx,%rcx
    xorq    %rsi,%rsi
    xorq    %rdi,%rdi
    xorq    %rbp,%rbp
    xorq    %r8,%r8
    xorq    %r9,%r9
    xorq    %r10,%r10
    xorq    %r11,%r11
    xorq    %r12,%r12
    xorq    %r13,%r13
    xorq    %r14,%r14
    xorq    %r15,%r15
    movq    %r11,%ds
    movq    %r11,%es
    movq    %r11,%fs
    movq    %r11,%gs
    wrfsbase %r11
    wrgsbase %r11
    fninit
    pop     %rdi
    iretq
