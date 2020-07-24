# SPDX-License-Identifier: Apache-2.0

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
    # Preserve registers not preserved by vDSO
    .cfi_startproc
    rpush   %r15
    rpush   %r14
    rpush   %r13
    rpush   %r12

    # Prepare stack for vDSO
    dpush   0x38(%rsp)          # exit handler
    dpush   0x38(%rsp)          # exception info
    dpush   0x38(%rsp)          # tcs

    call    *0x58(%rsp)         # __vdso_sgx_enter_enclave()

    add    $0x18, %rsp
    .cfi_adjust_cfa_offset  -0x18

    dpop    %r12
    dpop    %r13
    dpop    %r14
    dpop    %r15
    ret
    .cfi_endproc
