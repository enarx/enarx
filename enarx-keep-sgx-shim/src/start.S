# SPDX-License-Identifier: Apache-2.0

#define GPR     (4096 - 184)
#define RSP     (GPR + 32)

#define MISC    (GPR - 16)
#define SRSP    (MISC - 8)

#define STACK   (9 * 8)

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

# Clear the extended CPU state (clobbers %rax and %rdx)
.macro zerox
    movq    $~0,                    %rdx            # set mask for xrstor in rdx
    movq    $~0,                    %rax            # set mask for xrstor in rax
    xrstor  xsave(%rip)                             # clear xtd cpu state with synthetic state
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
    .globl enclave
    .type enclave, @function
enclave:
    xchg    %rbx,                   %rcx            # Swap TCS and next instruction.
    add     $4096,                  %rcx            # %rcx = &Layout
    cmp     $0,                     %rax            # If CSSA > 0...
    jne     .Levent                                 # ... restore stack from AEX[CSSA-1].

    # Clear unused registers and clear extended CPU state
    zerop
    zerot
    xor     %rax,                   %rax
    push    %rdx
    zerox
    pop     %rdx

    # Set the stack pointer and jump to Rust
    mov     STACK(%rcx),            %rsp
    jmp     entry

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
    mov     $~0,                    %r11            # Indicate ERESUME to VDSO handler

    # ENCLU[EEXIT]
.Leexit:
    loadp                                           # Load preserved registers
    pop     %rsp                                    # Restore the untrusted stack
    zerox                                           # Clear the extended CPU state
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
    loadp                                           # Restore trusted preserved registers

    movq    $~0,                    %rdx            # Set mask for xrstor in rdx
    movq    $~0,                    %rax            # Set mask for xrstor in rax
    xrstor  (%rsp)                                  # Restore extended CPU state
    mov     %rbx,                   %rsp            # Restore stack after aligned xsave area

    mov     %rdi,                   %rax            # Correct syscall return value register
    zeroa                                           # Clear the argument registers
    zerot                                           # Clear the temporary registers
    zerof   %r11                                    # Clear CPU flags
    ret                                             # Jump to address on the stack

    # int syscall(rdi, rsi, rdx, aex, r8, r9, r10, rax, ctx);
    .text
    .globl syscall
    .type syscall, @function
syscall:
    # Save stack pointer, allocate space, and set
    # 64-byte alignment on stack for xsavec
    mov     %rsp,                   %rbx
    sub     $4096,                  %rsp
    and     $(-0x40),               %rsp

    # Zero the xsave header area on stack
    movq    $0,        512(%rsp)
    movq    $0,        520(%rsp)
    movq    $0,        528(%rsp)
    movq    $0,        536(%rsp)
    movq    $0,        544(%rsp)
    movq    $0,        552(%rsp)
    movq    $0,        560(%rsp)
    movq    $0,        568(%rsp)

    # Set mask and perform xsavec
    movq    $~0,                   %rdx
    movq    $~0,                   %rax
    xsavec (%rsp)

    savep                                           # Save preserved registers
    mov     %rsp,                   SRSP(%rcx)      # Save restoration stack pointer

    mov     0x38(%rsp),             %r10            # Export %r10
    mov     0x40(%rsp),             %r11            # Export %rax in %r11
    mov     0x48(%rsp),             %rsp            # Get the exit context

    xor     %rcx,                   %rcx            # Clear %rcx
    zerof   %rcx                                    # Clear CPU flags
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
