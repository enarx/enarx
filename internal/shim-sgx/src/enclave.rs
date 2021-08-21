// SPDX-License-Identifier: Apache-2.0

//! The Enclave entry and exit
//!
//! Provides enclave EENTER entry point and a `syscall` interface.

pub enum Context {}

pub use _internal::syscall;

mod _internal {
    use crate::enclave::Context;
    use crate::entry::entry;
    use crate::event::event;
    use const_default::ConstDefault;
    use rcrt1::_dyn_reloc;
    use sallyport::syscall::SYS_ENARX_ERESUME;
    use sgx::types::ssa::StateSaveArea;
    use xsave::XSave;

    const GPR: u64 = 4096 - 184;
    const RSPO: u64 = GPR + 32;
    const MISC: u64 = GPR - 16;
    const SRSP: u64 = MISC - 8;

    const STACK: u64 = 9 * 8;
    const SHIM: u64 = 10 * 8;

    /// Clear CPU flags, extended state and temporary registers (`r10` and `r11`)
    ///
    /// This function clears CPU state during enclave transitions.
    #[naked]
    extern "C" fn clearx() {
        static XSAVE: XSave = XSave::DEFAULT;

        unsafe {
            asm!(
                // Clear all temporary registers
                "xor    r10,    r10",
                "xor    r11,    r11",

                // Clear CPU flags
                "add    r11,    r11",
                "cld",

                // Clear the extended CPU state
                "push    rax            ",  // Save rax
                "push    rdx            ",  // Save rdx
                "mov     rdx,   ~0      ",  // Set mask for xrstor in rdx
                "mov     rax,   ~0      ",  // Set mask for xrstor in rax
                "xrstor  [rip + {XSAVE}]",  // Clear xCPU state with synthetic state
                "pop     rdx            ",  // Restore rdx
                "pop     rax            ",  // Restore rax

                "ret",

                XSAVE = sym XSAVE,
                options(noreturn)
            );
        }
    }

    /// Clears parameter registers
    ///
    /// # Safety
    ///
    /// This function should be safe as it only modifies non-preserved
    /// registers. It really doesn't even need to be a naked function
    /// except that Rust tries really hard to put `rax` on the stack
    /// and then pops it off into a random register (usually `rcx`).
    #[naked]
    extern "sysv64" fn clearp() {
        unsafe {
            asm!(
                "xor    rax,    rax",
                "xor    rdi,    rdi",
                "xor    rsi,    rsi",
                "xor    rdx,    rdx",
                "xor    rcx,    rcx",
                "xor    r8,     r8",
                "xor    r9,     r9",
                "ret",
                options(noreturn)
            )
        }
    }

    /// Perform relocation
    ///
    /// # Safety
    ///
    /// This function does not follow any established calling convention. It
    /// has the following requirements:
    ///   * `rsp` must point to a stack with the return address (i.e. `call`)
    ///   * `rcx` must contain the address of the `Layout`
    ///
    /// Upon return, all general-purpose registers will have been preserved.
    #[naked]
    unsafe extern "sysv64" fn relocate() {
        asm!(
            "push   rax",
            "push   rdi",
            "push   rsi",
            "push   rdx",
            "push   rcx",
            "push   r8",
            "push   r9",
            "push   r10",
            "push   r11",

            "mov    rsi,    [rcx + {SHIM}]  ", // rsi = shim load offset (Layout.shim.start)
            ".hidden _DYNAMIC               ",
            "lea    rdi,    [rip + _DYNAMIC]", // rdi = address of _DYNAMIC section
            ".hidden {DYN_RELOC}            ",
            "call   {DYN_RELOC}             ", // relocate the dynamic symbols

            "pop    r11",
            "pop    r10",
            "pop    r9",
            "pop    r8",
            "pop    rcx",
            "pop    rdx",
            "pop    rsi",
            "pop    rdi",
            "pop    rax",

            "ret",

            SHIM = const SHIM,
            DYN_RELOC = sym _dyn_reloc,
            options(noreturn)
        )
    }

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
    #[naked]
    pub unsafe extern "sysv64" fn _start() -> ! {
        asm!("
    xchg    rcx,                    rbx             # Swap TCS and next instruction.
    add     rcx,                    4096            # rcx = &Layout
    cmp     rax,                    0               # If CSSA > 0...
    jne     2f                                      # ... restore stack from AEX[CSSA-1].

    mov     rsp,          QWORD PTR [rcx + {STACK}] # Set stack pointer

    call    {CLEARX}                                # Clear CPU state
    call    {RELOC}                                 # Relocate symbols
    call    {ENTRY}                                 # Jump to Rust

# CSSA != 0
2:
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
    jne     {RET_FROM_SYSCALL}                      # ... finish the job.

    push    rsp                                     # Argument for event()
    push    r11                                     # Argument for event()

    # void event(rdi, rsi, rdx, layout, r8, r9, &aex[CSSA-1], ctx);
    call    {CLEARX}                                # Clear CPU state
    call    {event}                                 # Call event()
    call    {CLEARX}                                # Clear CPU state
    call    {CLEARP}                                # Clear parameter registers
    add     rsp,                    16              # Remove parameters from stack

    # Indicate ERESUME to VDSO handler
    mov     r11,                    {SYS_ENARX_ERESUME}
    jmp     {EEXIT}
    ",
        RSPO = const RSPO,
        SRSP = const SRSP,
        STACK = const STACK,
        SYS_ENARX_ERESUME = const SYS_ENARX_ERESUME,
        CLEARX = sym clearx,
        CLEARP = sym clearp,
        event = sym event,
        RELOC = sym relocate,
        ENTRY = sym entry,
        EEXIT = sym enclu_eexit,
        RET_FROM_SYSCALL = sym ret_from_syscall,
        options(noreturn)
        )
    }

    #[no_mangle]
    #[naked]
    pub unsafe extern "sysv64" fn enclu_eexit() -> ! {
        asm!("
    # ENCLU[EEXIT]
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

    jmp     {RET_FROM_SYSCALL}
    ",
        RET_FROM_SYSCALL = sym ret_from_syscall,
        options(noreturn)
        )
    }

    #[no_mangle]
    #[naked]
    pub unsafe extern "sysv64" fn ret_from_syscall() -> ! {
        asm!("
# rax = syscall return stack pointer
# rbx = next non-enclave instruction
# rcx = &TCS
# r10 = untrusted stack pointer
# r11 = &aex[CSSA - 1]
# rsp = trusted stack pointer
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

    # Clear state
    sub     rsp,    8
    call    {CLEARX}
    call    {CLEARP}
    add     rsp,    8

    ret                                             # Jump to address on the stack
    ",
        SRSP = const SRSP,
        CLEARX = sym clearx,
        CLEARP = sym clearp,
        options(noreturn)
        )
    }

    #[naked]
    pub unsafe extern "sysv64" fn syscall(aex: &mut StateSaveArea, ctx: &Context) -> u64 {
        asm!("
    # int syscall(rdi = aex, rsi = ctx);

    # Save preserved registers (except rsp)
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15

    mov     QWORD PTR [rdi + {SRSP}],   rsp # Save restoration stack pointer

    push    rsi
    call    {CLEARX}
    call    {CLEARP}
    pop     rsp                             # Get exit context

    jmp     {EEXIT}
    ",
        SRSP = const SRSP,
        CLEARX = sym clearx,
        CLEARP = sym clearp,
        EEXIT = sym enclu_eexit,
        options(noreturn)
        )
    }
}
