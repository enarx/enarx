# SPDX-License-Identifier: Apache-2.0

#define EFAULT  14
#define EENTER  2
#define ERESUME 3
#define INVOP   6

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
    .global enclave_enter
    .type enclave_enter, @function
enclave_enter:
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

    mov     0x70(%rsp), %eax    # Leaf
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
    .global enclave_handle
    .type enclave_handle, @function
enclave_handle:
    mov     16(%rsp),   %rax        # %rax = ret parameter
    cmp     $0,         %rax        # enclave EEXIT
    je      .Leexit
    cmp     $-EFAULT,   %eax        # enclave AEX
    je      .Laex

.Ldone:
    ret

.Leexit:
    cmp     $~0,        %r11        # No syscall
    mov     $ERESUME,   %rax        # %rax = ERESUME
    je      .Ldone

    mov     %r11,       %rax        # %rax is passed in %r11
    syscall
    mov     %rax,       %rdi
    mov     $EENTER,    %rax        # %rax = EENTER
    ret

.Laex:
    mov     24(%rsp),   %rax        # %rax = @e
    cmp     $0,         %rax
    je      .Lfault

    mov     4(%rax),    %ax         # %ax = e->trapnr (16 bits)
    cmp     $INVOP,     %ax         # trapnr == invalid opcode
    jne     .Lfault

    mov     $EENTER,    %rax        # Re-enter the enclave to
    ret                             # handle the invalid opcode.

.Lfault:
    mov     $-EFAULT,   %rax
    ret
