# SPDX-License-Identifier: Apache-2.0

    .text
    .globl enarx_eenter
    .type enarx_eenter, @function
enarx_eenter:
    push   %rbx

    mov    $2,        %rax    # EENTER
    mov    %rdi,      %rbx    # TCS Address
    lea    aep(%rip), %rcx    # AEP
    enclu                     # Call ENCLU[EENTER]

    pop    %rbx
    ret

aep:
    enclu                     # Call ENCLU[EENTER]

    mov    $3,        %rax    # ERESUME (implicit: TCS address)
    lea    aep(%rip), %rcx    # AEP
    enclu                     # Call ENCLU[ERESUME]
