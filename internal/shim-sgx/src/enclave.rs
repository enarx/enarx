// SPDX-License-Identifier: Apache-2.0

//! The Enclave entry and exit
//!
//! Provides enclave EENTER entry point and a `syscall` interface.

mod _internal {
    use const_default::ConstDefault;
    use rcrt1::_dyn_reloc;
    use xsave::XSave;

    const EEXIT: u64 = 4;

    const GPR: u64 = 4096 - 184;
    const RSPO: u64 = GPR + 32;

    const STACK: u64 = 9 * 8;
    const SHIM: u64 = 10 * 8;

    /// Clear CPU flags, extended state and temporary registers (`r10` and `r11`)
    ///
    /// This function clears CPU state during enclave transitions.
    ///
    /// # Safety
    ///
    /// This function should be safe as it only modifies non-preserved
    /// registers. In fact, in addition to the declared calling convention,
    /// we promise not to modify any of the parameter registers.
    #[naked]
    extern "sysv64" fn clearx() {
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
            )
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
    ///
    /// # Safety
    ///
    /// Do not call this function from Rust. It is the entry point for SGX.
    #[naked]
    #[no_mangle]
    pub unsafe extern "sysv64" fn _start() -> ! {
        asm!(
            "xchg   rcx,    rbx                 ",  // Swap TCS and next instruction
            "add    rcx,    4096                ",  // rcx = &Layout

            // Find stack pointer for CSSA == 0
            "cmp    rax,    0                   ",  // If CSSA > 0
            "jne    2f                          ",  // ... jump to the next section
            "mov    r10,    [rcx + {STACK}]     ",  // r10 = stack pointer
            "jmp    3f                          ",  // Jump to stack setup

            // Find stack pointer for CSSA > 0
            "2:                                 ",
            "mov    r10,    rax                 ",  // r10 = CSSA
            "shl    r10,    12                  ",  // r10 = CSSA * 4096
            "mov    r10,    [rcx + r10 + {RSPO}]",  // r10 = SSA[CSSA - 1].gpr.rsp
            "sub    r10,    128                 ",  // Skip the red zone
            "jmp    3f                          ",  // Jump to stack setup

            // Setup the stack
            "3:                                 ",
            "and    r10,    ~0xf                ",  // Align the stack
            "xchg   rsp,    r10                 ",  // Swap r10 and rsp
            "sub    rsp,    8                   ",  // Align the stack
            "push   r10                         ",  // Store old stack

            // Do relocation if CSSA == 0
            "cmp    rax,    0                   ",  // If CSSA > 0
            "jne    4f                          ",  // ... jump to the next section
            "call   {RELOC}                     ",  // Relocate symbols

            // Clear, call Rust, clear
            "4:                                 ",
            "push   rcx                         ",  // Save &Layout
            "push   rax                         ",  // Save CSSA
            "mov    rcx,    rsp                 ",  // Setup argument
            "call   {CLEARX}                    ",  // Clear CPU state
            "call   {ENTRY}                     ",  // Jump to Rust
            "call   {CLEARX}                    ",  // Clear CPU state
            "call   {CLEARP}                    ",  // Clear parameter registers
            "add    rsp,    16                  ",  // Remove arguments from stack

            // Exit
            "pop    rsp                         ",  // Restore old stack
            "mov    rax,    {EEXIT}             ",  // rax = EEXIT
            "enclu                              ",  // Exit enclave

            CLEARX = sym clearx,
            CLEARP = sym clearp,
            RELOC = sym relocate,
            ENTRY = sym crate::main,
            EEXIT = const EEXIT,
            STACK = const STACK,
            RSPO = const RSPO,
            options(noreturn)
        )
    }
}
