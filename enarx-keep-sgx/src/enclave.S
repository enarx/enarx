# SPDX-License-Identifier: Apache-2.0

#define EENTER  2
#define ERESUME 3

.macro dpush arg
    push                    \arg
    .cfi_adjust_cfa_offset  8
.endm

.macro dpop arg
    pop                     \arg
    .cfi_adjust_cfa_offset  -8
.endm

.macro rpush reg
    dpush                   \reg
    .cfi_rel_offset         \reg, 0
.endm

    .text
    .global eenter
    .type eenter, @function
eenter:
    .cfi_startproc
    rpush   %r15
    rpush   %r14
    rpush   %r13
    rpush   %r12
    rpush   %rbx

    dpush   $0
    dpush   0x48(%rsp)
    dpush   0x48(%rsp)
    dpush   0x48(%rsp)

    call    *0x68(%rsp)         # __vdso_sgx_enter_enclave()

    add    $0x20, %rsp
    .cfi_adjust_cfa_offset  -0x20

    dpop    %rbx
    dpop    %r12
    dpop    %r13
    dpop    %r14
    dpop    %r15
    ret
    .cfi_endproc

    .text
    .global handle
    .type handle, @function
handle:
    mov     16(%rsp),   %rax        # %rax = ret parameter
    cmp     $0,         %rax        # enclave EEXIT
    je      .Leexit
    ret

.Leexit:
    cmp     $~0,        %r11        # Is a syscall?
    jne     .Lsyscall
    mov     $ERESUME,   %rax
    ret

.Lsyscall:
    mov     %r11,       %rax        # %rax is passed in %r11
    syscall
    mov     %rax,       %rdi        # Pass return value in %rdi
    mov     $EENTER,    %rax        # %rax = EENTER
    ret
