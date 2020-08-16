# SPDX-License-Identifier: Apache-2.0

#define GPR     (4096 - 184)
#define RSP     (GPR + 32)

#define MISC    (GPR - 16)
#define SRSP    (MISC - 8)

#define STACK   (9 * 8)
#define SHIM    (10 * 8)

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

# Clear the extended CPU state
.macro zerox
    push    %rax                                    # Save %rax
    push    %rdx                                    # Save %rdx
    movq    $~0,                    %rdx            # Set mask for xrstor in %rdx
    movq    $~0,                    %rax            # Set mask for xrstor in %rax
    xrstor  xsave(%rip)                             # Clear xCPU state with synthetic state
    pop     %rdx                                    # Restore %rdx
    pop     %rax                                    # Restore %rax
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

    .section .rodata
    .align 64
xsave:                          # An initialized synthetic xsave area
# Legacy
    .fill   1, 4, 0x037F        # FCW
    .fill   5, 4, 0
    .fill   1, 4, 0x1F80        # MXCSR
    .fill   1, 4, 0xFFFF        # MXCSR_MASK
    .fill   60, 8, 0

# Header
    .fill   1, 8, 0             # XSTATE_BV
    .fill   1, 8, 1 << 63       # XCOMP_BV (compaction mode)
    .fill   6, 8, 0

# This function is called during EENTER. Its inputs are as follows:
#  %rax = The current SSA index. (i.e. %rbx->cssa)
#  %rbx = The address of the TCS.
#  %rcx = The next address after the EENTER instruction.
#
#  If %rax == 0, we are doing normal execution.
#  Otherwise, we are handling an exception.
   .text
   .hidden _DYNAMIC
   .globl _dyn_reloc
   .globl _start
   .type _start, @function
_start:
    xchg    %rbx,                   %rcx            # Swap TCS and next instruction.
    add     $4096,                  %rcx            # %rcx = &Layout
    cmp     $0,                     %rax            # If CSSA > 0...
    jne     .Levent                                 # ... restore stack from AEX[CSSA-1].

    mov     STACK(%rcx),            %rsp            # Set stack pointer
    zerop                                           # Clear preserved registers
    zerot                                           # Clear temporary registers
    zerox                                           # Clear xCPU state
    xor     %rax,                   %rax            # Clear %rax

    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11

    # relocate the dynamic symbols
    # %rdi - address of _DYNAMIC section
    # %rsi - shim load offset from Layout.shim.start
    mov    SHIM(%rcx),              %rsi
    lea    _DYNAMIC(%rip),          %rdi
    call   _dyn_reloc

    popq    %r11
    popq    %r10
    popq    %r9
    popq    %r8
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %rdi

    xor     %rax,                   %rax            # Clear %rax

    call    entry                                   # Jump to Rust

# CSSA != 0
.Levent:
    shl     $12,                    %rax            # %rax = CSSA * 4096
    mov     %rcx,                   %r11            # %r11 = &Layout
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
    zerox                                           # Clear xCPU state
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

    # int syscall(rdi = aex, rsi = ctx);
    .text
    .globl syscall
    .type syscall, @function
syscall:
    savep                                           # Save preserved registers
    mov     %rsp,                   SRSP(%rdi)      # Save restoration stack pointer

    zerox                                           # Clear xCPU state
    xor     %rcx,                   %rcx            # Clear %rcx
    zerof   %rcx                                    # Clear CPU flags
    mov     %rsi,                   %rsp            # Get exit context

    jmp     .Leexit

    # _Noreturn void exit(code);
    .text
    .globl exit
    .type exit, @function
exit:
    mov     $60,                    %rax
    syscall
    ud2

    # _Noreturn void jump(rsp, fnc);
    .text
    .globl jump
    .type jump, @function
jump:
    mov     %rdi,                   %rsp
    jmp     *%rsi
