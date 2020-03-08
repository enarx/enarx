# SPDX-License-Identifier: Apache-2.0

#define NSSA    2
#define ALGN    (2 * 1024 * 1024)
#define STCK    (8 * 1024 * 1024)
#define HEAP    (128 * 1024 * 1024)

    .section ".enarx.ctx", "aw"
    .globl ctx
    .type ctx, @object
ctx:
tcs:                            # The TCS page
    .align  4096
    .fill   1, 8, 0             # STATE (set by CPU)
    .fill   1, 8, 0             # FLAGS
    .quad   aex - tcs           # OSSA
    .fill   1, 4, 0             # CSSA (set by CPU)
    .fill   1, 4, NSSA          # NSSA
    .quad   enclave - tcs       # OENTRY
    .fill   1, 8, 0             # AEP (set by EENTER and ERESUME)
    .fill   1, 8, 0             # OFSBASE
    .fill   1, 8, 0             # OGSBASE
    .fill   1, 4, 0xFFFFFFFF    # FSLIMIT
    .fill   1, 4, 0xFFFFFFFF    # GSLIMIT
    .fill   4024, 1, 0          # Reserved
aex:                            # The AEX SSA region
    .rept   NSSA
    .align  4096
    .fill   4096, 1, 0
    .endr

    .section ".enarx.stk", "aw", @nobits
    .type   stk, @object
    .size   stk, STCK
    .globl  stk
    .align  ALGN
    .zero   STCK
stk:                            # The top of the secure stack

    .section ".enarx.shp", "aw", @nobits
    .type   shp, @object
    .size   shp, HEAP
    .globl  shp
shp:                            # The bottom of the secure heap
    .align  ALGN
    .zero   HEAP

# This function is called during EENTER. Its inputs are as follows:
#  %rax = The current SSA index. (i.e. %rbx->cssa)
#  %rbx = The address of the TCS.
#  %rcx = The next address after the EENTER instruction.
#
#  If %rax == 0, we are doing normal execution.
#  Otherwise, we are handling an exception.
    .text
    .globl enclave
    .type enclave, @function
enclave:
    lea     stk(%rip),              %rdi            # Get the stack address
    xchg    %rsp,                   %rdi            # Swap stacks
    push    %rdi                                    # Store the old stack
    push    %rcx                                    # Store next non-enclave addr

    cmp     $0,                     %rax            # If CSSA == 0 ...
    jne     .event                                  # ... go to .event

.entry:
    ud2                                             # Synthetic bad instruction
    jmp     .eexit                                  # Do EEXIT

.event:
    mov     %rax,                   %rdi            # %rdi = CSSA
    shl     $12,                    %rdi            # %rdi = CSSA * 4096
    add     %rbx,                   %rdi            # %rdi = aex[CSSA - 1]
    call    event                                   # Call our event handler

.eexit:
    pop     %rbx                                    # Restore next non-enclave addr
    pop     %rsp                                    # Restore old stack
    mov     $4,                     %rax            # EEXIT
    enclu                                           # ENCLU[EEXIT]
