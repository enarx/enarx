// SPDX-License-Identifier: Apache-2.0

//! The Enclave entry and exit
//!
//! Provides enclave EENTER entry point and a `syscall` interface.
use sgx::types::ssa::StateSaveArea;

pub enum Context {}

extern "C" {
    pub fn syscall(aex: &mut StateSaveArea, ctx: &Context) -> u64;
}

mod _internal {
    use crate::event::event;
    use const_default::ConstDefault;
    use rcrt1::_dyn_reloc;
    use sallyport::syscall::SYS_ENARX_ERESUME;
    use xsave::XSave;

    const GPR: u64 = 4096 - 184;
    const RSPO: u64 = GPR + 32;
    const MISC: u64 = GPR - 16;
    const SRSP: u64 = MISC - 8;

    const STACK: u64 = 9 * 8;
    const SHIM: u64 = 10 * 8;

    #[no_mangle]
    pub static XSAVE: XSave = XSave::DEFAULT;

    /// Entry point
    ///
    /// This function is called during EENTER. Its inputs are as follows:
    ///  rax = The current SSA index. (i.e. rbx->cssa)
    ///  rbx = The address of the TCS.
    ///  rcx = The next address after the EENTER instruction.
    ///
    ///  If rax == 0, we are doing normal execution.
    ///  Otherwise, we are handling an exception.
    #[no_mangle]
    #[allow(named_asm_labels)]
    #[naked]
    pub unsafe extern "sysv64" fn _start() -> ! {
        asm!("
    xchg    rcx,                    rbx             # Swap TCS and next instruction.
    add     rcx,                    4096            # rcx = &Layout
    cmp     rax,                    0               # If CSSA > 0...
    jne     .Levent                                 # ... restore stack from AEX[CSSA-1].

    mov     rsp,          QWORD PTR [rcx + {STACK}] # Set stack pointer

    # Clear all preserved (callee-saved) registers (except rsp)
    xor     rbx,                    rbx
    xor     rbp,                    rbp
    xor     r12,                    r12
    xor     r13,                    r13
    xor     r14,                    r14
    xor     r15,                    r15

    # Clear all temporary registers
    xor     r10,                    r10
    xor     r11,                    r11

    # Clear the extended CPU state
    push    rax                                     # Save rax
    push    rdx                                     # Save rdx
    mov     rdx,                    ~0              # Set mask for xrstor in rdx
    mov     rax,                    ~0              # Set mask for xrstor in rax
    xrstor  [rip + {XSAVE}]                         # Clear xCPU state with synthetic state
    pop     rdx                                     # Restore rdx
    pop     rax                                     # Restore rax

    xor     rax,                    rax             # Clear rax

    push    rdi
    push    rsi
    push    rdx
    push    rcx
    push    r8
    push    r9
    push    r10
    push    r11

    # relocate the dynamic symbols
    # rdi - address of _DYNAMIC section
    # rsi - shim load offset from Layout.shim.start
    mov     rsi,          QWORD PTR [rcx + {SHIM}]
    .hidden _DYNAMIC
    lea     rdi,                    [rip + _DYNAMIC]
    .hidden {DYN_RELOC}
    call    {DYN_RELOC}

    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rcx
    pop     rdx
    pop     rsi
    pop     rdi

    xor     rax,                    rax             # Clear rax

    call    entry                                   # Jump to Rust

# CSSA != 0
.Levent:
    shl     rax,                    12              # rax = CSSA * 4096
    mov     r11,                    rcx             # r11 = &Layout
    add     r11,                    rax             # r11 = &aex[CSSA - 1]

    mov     r10,          QWORD PTR [{RSPO} + r11]  # r10 = aex[CSSA - 1].gpr.rsp
    sub     r10,                    128             # Skip the red zone
    and     r10,                    ~0xf            # Align

    mov     rax,          QWORD PTR [{SRSP} + r11]  # rax = syscall return stack pointer

    # rax = syscall return stack pointer
    # rbx = next non-enclave instruction
    # rcx = &layout
    # r10 = trusted stack pointer
    # r11 = &aex[CSSA - 1]
    # rsp = untrusted stack pointer
    xchg    rsp,                    r10             # Swap to trusted stack
    push    0                                       # Align stack
    push    r10                                     # Save untrusted rsp

    # Save untrusted preserved registers (except rsp)
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15

    cmp     rax,                    0               # If we are returning from a syscall...
    jne     .Lsyscall                               # ... finish the job.

    push    rsp                                     # Argument for event()
    push    r11                                     # Argument for event()

    # Clear all preserved (callee-saved) registers (except rsp)
    xor     rbx,                    rbx
    xor     rbp,                    rbp
    xor     r12,                    r12
    xor     r13,                    r13
    xor     r14,                    r14
    xor     r15,                    r15

    # Clear all temporary registers
    xor     r10,                    r10
    xor     r11,                    r11

    # Clear CPU flags
    add     r11,                    r11
    cld

    # void event(rdi, rsi, rdx, layout, r8, r9, &aex[CSSA-1], ctx);
    call    {event}                                 # Call event()
    add     rsp,                    16              # Remove parameters from stack

    # Prepare CPU context for exit
    # Clear all temporary registers
    xor     r10,                    r10
    xor     r11,                    r11

    # Clear all argument registers
    xor     rcx,                    rcx
    xor     rdx,                    rdx
    xor     rsi,                    rsi
    xor     rdi,                    rdi
    xor     r8,                     r8
    xor     r9,                     r9

    # Clear CPU flags
    add     r11,                    r11
    cld

    # Clear the extended CPU state
    push    rax                                     # Save rax
    push    rdx                                     # Save rdx
    mov     rdx,                    ~0              # Set mask for xrstor in rdx
    mov     rax,                    ~0              # Set mask for xrstor in rax
    xrstor  [rip + {XSAVE}]                         # Clear xCPU state with synthetic state
    pop     rdx                                     # Restore rdx
    pop     rax                                     # Restore rax

    # Indicate ERESUME to VDSO handler
    mov     r11,                    {SYS_ENARX_ERESUME}

    # ENCLU[EEXIT]
.Leexit:
    # Load preserved registers (except rsp)
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx

    pop     rsp                                     # Restore the untrusted stack
    mov     rax,                    4
    enclu

# rax = syscall return stack pointer
# rbx = next non-enclave instruction
# rcx = &TCS
# r10 = untrusted stack pointer
# r11 = &aex[CSSA - 1]
# rsp = trusted stack pointer
.Lsyscall:
    mov     QWORD PTR [r11 + {SRSP}], 0             # Clear syscall return stack pointer field
    mov     rsp,                    rax             # Restore the syscall return stack pointer
    mov     rax,                    rdi             # Correct syscall return value register

    # Load trusted preserved registers (except rsp)
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx

    # Clear all argument registers
    xor     rcx,                    rcx
    xor     rdx,                    rdx
    xor     rsi,                    rsi
    xor     rdi,                    rdi
    xor     r8,                     r8
    xor     r9,                     r9

    # Clear all temporary registers
    xor     r10,                    r10
    xor     r11,                    r11

    # Clear CPU flags
    add     r11,                    r11
    cld

    ret                                             # Jump to address on the stack

    .global syscall
syscall:
    # int syscall(rdi = aex, rsi = ctx);

    # Save preserved registers (except rsp)
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15

    mov     QWORD PTR [rdi + {SRSP}], rsp             # Save restoration stack pointer

    # Clear the extended CPU state
    push    rax                                     # Save rax
    push    rdx                                     # Save rdx
    mov     rdx,                    ~0              # Set mask for xrstor in rdx
    mov     rax,                    ~0              # Set mask for xrstor in rax

    xrstor  [rip + {XSAVE}]                         # Clear xCPU state with synthetic state
    pop     rdx                                     # Restore rdx
    pop     rax                                     # Restore rax

    xor     rcx,                    rcx             # Clear rcx

    # Clear CPU flags
    add     rcx,                    rcx
    cld

    mov     rsp,                    rsi             # Get exit context

    jmp     .Leexit
    ",
        RSPO = const RSPO,
        SRSP = const SRSP,
        STACK = const STACK,
        SHIM = const SHIM,
        SYS_ENARX_ERESUME = const SYS_ENARX_ERESUME,
        XSAVE = sym XSAVE,
        event = sym event,
        DYN_RELOC = sym _dyn_reloc,
        options(noreturn)
        )
    }
}
