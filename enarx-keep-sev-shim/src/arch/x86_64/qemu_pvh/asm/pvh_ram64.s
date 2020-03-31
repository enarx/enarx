# SPDX-License-Identifier: Apache-2.0

.section .ram64, "ax"
.global ram64_start
.code64

ram64_start:
    # Indicate (via serial) that we are in long/64-bit mode
    /*
    movw $0x2f8, %dx
    movb $'L', %al
    outb %al, %dx
    movb $'\n', %al
    outb %al, %dx
    */


    # HvmStartInfo is in %rbp
    # move to first C argument
    movq %rbx, %rdi
    movabs $_start_e820,%rax
    jmp _setup_pto

.halt_loop:
    hlt
    jmp .halt_loop

