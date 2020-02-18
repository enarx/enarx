# SPDX-License-Identifier: Apache-2.0

# This function is called during EENTER. Its inputs are as follows:
#  %rax = The current SSA index. (i.e. %rbx->cssa)
#  %rbx = The offset of the TCS inside the enclave.
#  %rcx = The next address after the EENTER instruction.
#
#  If %rax == 0, we are doing normal execution.
#  Otherwise, we are handling an exception.
#
      .text
      .globl _start
      .type _start, @function
_start:
    mov     $4,   %rax # EEXIT
    mov     %rcx, %rbx # Next instruction
    enclu              # ENCLU[EEXIT]

    # Clear general registers.
#    xor     %r8,             %r8
#    xor     %r9,             %r9
#    xor     %r10,            %r10
#    xor     %r11,            %r11
#    xor     %r12,            %r12
#    xor     %r13,            %r13
#    xor     %r14,            %r14
#    xor     %r15,            %r15

    # Clear CPU flags.
#    add     %r15,            %r15
#    cld

    # Set up the stack at a random offset.
#    rdrand  %rbp                   # Get a random number.
#    mov     stack(%rip),     %rsp  # Set the top of the stack.
#    and     $0xf000,         %rbp  # Clamp to a random page offset.
#    sub     %rbp,            %rsp  # Move by the page offset.
#    xor     %rbp,            %rbp  # Clear the base pointer.

#    jmp     *%rax
#    ud2
