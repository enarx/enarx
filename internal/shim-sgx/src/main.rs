// SPDX-License-Identifier: Apache-2.0

//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![no_std]
#![feature(asm)]
#![feature(naked_functions)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![no_main]

extern crate compiler_builtins;
extern crate rcrt1;

#[panic_handler]
#[cfg(not(test))]
#[allow(clippy::empty_loop)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// _Unwind_Resume is only needed in the `debug` profile
///
/// even though this project has `panic=abort`
/// it seems like the debug libc.rlib has some references
/// with unwinding
/// See also: https://github.com/rust-lang/rust/issues/47493
#[cfg(debug_assertions)]
#[no_mangle]
extern "C" fn _Unwind_Resume() {
    unimplemented!();
}

/// rust_eh_personality is only needed in the `debug` profile
///
/// even though this project has `panic=abort`
/// it seems like the debug libc.rlib has some references
/// with unwinding
/// See also: https://github.com/rust-lang/rust/issues/47493
#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {
    unimplemented!();
}

// ============== REAL CODE HERE ===============

mod entry;
mod handler;
mod hostlib;

use hostlib::Layout;

use sallyport::Block;
use sgx::types::ssa::StateSaveArea;

const DEBUG: bool = false;

sallyport::declare_abi_version!();

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
    use const_default::ConstDefault;
    static XSAVE: xsave::XSave = xsave::XSave::DEFAULT;

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
    const SHIM: u64 = 10 * 8;

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
        DYN_RELOC = sym rcrt1::dyn_reloc,
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
    // The constant for ENCLU[EEXIT]
    const EEXIT: u64 = 4;

    // GPRO = offset_of!(StateSaveArea, gpr);
    const GPRO: u64 = 4096 - 184;

    // RSPO = offset_of!(StateSaveArea, gpr.rsp);
    const RSPO: u64 = GPRO + 32;

    const STACK: u64 = 9 * 8;

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
        ENTRY = sym main,
        EEXIT = const EEXIT,
        STACK = const STACK,
        RSPO = const RSPO,
        options(noreturn)
    )
}

#[repr(C)]
struct Context {
    layout: hostlib::Layout,
    ssa: [StateSaveArea],
}

#[repr(C)]
struct Input {
    cssa: usize,
    ctx: &'static mut Context,
}

#[allow(unreachable_code)]
extern "C" fn main(
    _rdi: usize,
    _rsi: usize,
    rdx: &mut Block,
    rcx: &mut Input,
    _r8: usize,
    _r9: usize,
) {
    match rcx.cssa {
        0 => entry::entry(&rcx.ctx.layout),
        1 => handler::Handler::handle(&mut rcx.ctx.ssa[0].gpr, rdx, rcx.ctx.layout.heap),
        n => handler::Handler::finish(&mut rcx.ctx.ssa[n - 1].gpr),
    }
}
