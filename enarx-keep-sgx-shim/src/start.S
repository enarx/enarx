# SPDX-License-Identifier: Apache-2.0

#define NSSA    2
#define ALGN    (2 * 1024 * 1024)
#define STCK    (8 * 1024 * 1024)
#define HEAP    (128 * 1024 * 1024)

#define GPR     (4096 - 184)
#define RSP     (GPR + 32)

#define MISC    (GPR - 16)
#define SRSP    (MISC - 8)

# Clear all preserved (callee-saved) registers (except %rsp)
.macro  zerop
    xor     %rbx,                   %rbx
    xor     %rbp,                   %rbp
    xor     %r12,                   %r12
    xor     %r13,                   %r13
    xor     %r14,                   %r14
    xor     %r15,                   %r15
.endm

# Clear all argument registers
.macro  zeroa
    xor     %rcx,                   %rcx
    xor     %rdx,                   %rdx
    xor     %rsi,                   %rsi
    xor     %rdi,                   %rdi
    xor     %r8,                    %r8
    xor     %r9,                    %r9
.endm

# Clear all temporary registers
.macro  zerot
    xor     %r10,                   %r10
    xor     %r11,                   %r11
.endm

# Clear CPU flags using the supplied register (which MUST contain zero!)
.macro  zerof reg
    add     \reg,                   \reg
    cld
.endm

# Save preserved registers (except %rsp)
.macro  savep
    push    %rbx
    push    %rbp
    push    %r12
    push    %r13
    push    %r14
    push    %r15
.endm

# Load preserved registers (except %rsp)
.macro  loadp
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbp
    pop     %rbx
.endm

    .section ".enarx.tcs", "aw"
    .globl tcs
    .type tcs, @object
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
    .fill   1, 4, ~0            # FSLIMIT
    .fill   1, 4, ~0            # GSLIMIT
    .fill   4024, 1, 0          # Reserved

    .section ".enarx.aex", "aw", @nobits
    .globl aex
    .type aex, @object
aex:
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
stk:                            # The top of the trusted stack

    .section ".enarx.thp", "aw", @nobits
    .type   thp, @object
    .size   thp, HEAP
    .globl  thp
thp:                            # The bottom of the trusted heap
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
    xchg    %rbx,                   %rcx            # Swap TCS and next instruction.
    cmp     $0,                     %rax            # If CSSA > 0...
    jne     .Levent                                 # ... restore stack from AEX[CSSA-1].

    # Clear unused registers, set the stack pointer and jump to Rust
    zerop
    zerot
    xor     %rax,                   %rax
    lea     stk(%rip),              %rsp
    jmp     entry

# CSSA != 0
.Levent:
    dec     %rax                                    # %rax = CSSA - 1
    shl     $12,                    %rax            # %rax = (CSSA - 1) * 4096
    movabs  $aex,                   %r11            # %r11 = &aex
    add     %rax,                   %r11            # %r11 = &aex[CSSA - 1]

    mov     RSP(%r11),              %r10            # %r10 = aex[CSSA - 1].gpr.rsp
    sub     $128,                   %r10            # Skip the red zone
    and     $~0xf,                  %r10            # Align

    mov     SRSP(%r11),             %rax            # %rax = syscall return stack pointer

    # %rax = syscall return stack pointer
    # %rbx = next non-enclave instruction
    # %rcx = &TCS
    # %r10 = trusted stack pointer
    # %r11 = &aex[CSSA - 1]
    # %rsp = untrusted stack pointer
    xchg    %r10,                   %rsp            # Swap to trusted stack
    pushq   $0                                      # Align stack
    push    %r10                                    # Save untrusted %rsp
    savep                                           # Save untrusted preserved registers

    cmp     $0,                     %rax            # If we are returning from a syscall...
    jne     .Lsyscall                               # ... finish the job.

    push    %rsp                                    # Argument for event()
    push    %r11                                    # Argument for event()

    zerop                                           # Clear preserved registers
    zerot                                           # Clear temporary registers
    zerof   %r11                                    # Clear CPU flags

    # void event(rdi, rsi, rdx, tcs, r8, r9, &aex[CSSA-1], ctx);
    call    event                                   # Call event()
    add     $16,                    %rsp            # Remove parameters from stack

    # Prepare CPU context for exit
    zerot                                           # Clear temporary registers
    zeroa                                           # Clear argument registers
    zerof   %r11                                    # Clear CPU flags
    mov     $~0,                    %r11            # Indicate ERESUME to VDSO handler

    # ENCLU[EEXIT]
.Leexit:
    loadp                                           # Load preserved registers
    pop     %rsp                                    # Restore the untrusted stack
    mov     $4,                     %rax
    enclu

# %rax = syscall return stack pointer
# %rbx = next non-enclave instruction
# %rcx = &TCS
# %r10 = untrusted stack pointer
# %r11 = &aex[CSSA - 1]
# %rsp = trusted stack pointer
.Lsyscall:
    movq    $0,                     SRSP(%r11)      # Clear syscall return stack pointer field
    mov     %rax,                   %rsp            # Restore the syscall return stack pointer
    mov     %rdi,                   %rax            # Correct syscall return value register
    loadp                                           # Restore trusted preserved registers
    zeroa                                           # Clear the argument registers
    zerot                                           # Clear the temporary registers
    zerof   %r11                                    # Clear CPU flags
    ret                                             # Jump to address on the stack

    # int syscall(rdi, rsi, rdx, aex, r8, r9, r10, rax, ctx);
    .text
    .globl syscall
    .type syscall, @function
syscall:
    savep                                           # Save preserved registers
    mov     %rsp,                   SRSP(%rcx)      # Save restoration stack pointer

    mov     0x38(%rsp),             %r10            # Export %r10
    mov     0x40(%rsp),             %r11            # Export %rax in %r11
    mov     0x48(%rsp),             %rsp            # Get the exit context

    xor     %rcx,                   %rcx            # Clear %rcx
    zerof   %rcx                                    # Clear CPU flags
    jmp     .Leexit

    # Temporary test function
    # int do_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    .text
    .globl do_syscall
    .type do_syscall, @function
do_syscall:
    mov     %rcx,                   %r10
    mov     8(%rsp),                %rax
    syscall
    ret
