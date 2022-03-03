// SPDX-License-Identifier: Apache-2.0

//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![no_std]
#![feature(asm_const, asm_sym, naked_functions)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![no_main]

#[allow(unused_extern_crates)]
extern crate compiler_builtins;
#[allow(unused_extern_crates)]
extern crate rcrt1;

use core::arch::asm;

use shim_sgx::{entry, handler, ATTR, ENARX_EXEC_START, ENCL_SIZE, ENCL_SIZE_BITS, MISC};

#[panic_handler]
#[cfg(not(test))]
#[allow(clippy::empty_loop)]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
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

use noted::noted;
use sallyport::{elf::note, REQUIRES};
use sgx::parameters::{Attributes, MiscSelect};
use sgx::ssa::{GenPurposeRegs, StateSaveArea};

noted! {
    static NOTE_REQUIRES<note::NAME, note::REQUIRES, [u8; REQUIRES.len()]> = REQUIRES;

    static NOTE_BITS<note::NAME, note::sgx::BITS, u8> = ENCL_SIZE_BITS;
    static NOTE_SSAP<note::NAME, note::sgx::SSAP, u8> = 1;

    static NOTE_PID<note::NAME, note::sgx::PID, u16> = 0;
    static NOTE_SVN<note::NAME, note::sgx::SVN, u16> = 0;
    static NOTE_MISC<note::NAME, note::sgx::MISC, MiscSelect> = MISC;
    static NOTE_MISCMASK<note::NAME, note::sgx::MISCMASK, MiscSelect> = MISC;
    static NOTE_ATTR<note::NAME, note::sgx::ATTR, Attributes> = ATTR;
    static NOTE_ATTRMASK<note::NAME, note::sgx::ATTRMASK, Attributes> = ATTR;
}

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
    static XSAVE: xsave::XSave = <xsave::XSave as ConstDefault>::DEFAULT;

    unsafe {
        asm!(
            // Clear all temporary registers
            "xor    r10,    r10",
            "xor    r11,    r11",

            // Clear CPU state bits and DF/AC flags
            // Note: we can simply popfq an all-zero value, as system flags and
            // reserved bits are not writable from the user-space enclave
            "push    QWORD PTR 0",
            "popfq",

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

        "lea    rdi,    [rip + _DYNAMIC]", // rdi = address of _DYNAMIC section
        "mov    rsi,    -{SIZE}         ", // rsi = enclave start address mask
        "and    rsi,    rdi             ", // rsi = relocation address
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

        SIZE = const ENCL_SIZE,
        DYN_RELOC = sym rcrt1::dyn_reloc,
        options(noreturn)
    )
}

/// Entry point
///
/// This function is called during EENTER. Its inputs are as follows:
///
///  rax = The current SSA index. (i.e. rbx->cssa)
///  rbx = The address of the TCS.
///  rcx = The next address after the EENTER instruction.
///
/// If rax == 0, we are doing normal execution.
/// Otherwise, we are handling an exception.
///
/// # Safety
///
/// Do not call this function from Rust. It is the entry point for SGX.
#[naked]
#[no_mangle]
pub unsafe extern "sysv64" fn _start() -> ! {
    use core::mem::size_of;

    asm!(
        "cld                                ",  // Clear Direction Flag
        "xchg   rbx,    rcx                 ",  // rbx = exit address, rcx = TCS page

        // Find stack pointer for CSSA == 0
        "cmp    rax,    0                   ",  // If CSSA > 0
        "jne    2f                          ",  // ... jump to the next section
        "mov    r10,    rcx                 ",  // r10 = stack pointer
        "jmp    3f                          ",  // Jump to stack setup

        // Get the address of the previous SSA
        "2:                                 ",
        "mov    r10,    rax                 ",  // r10 = CSSA
        "shl    r10,    12                  ",  // r10 = CSSA * 4096
        "add    r10,    rcx                 ",  // r10 = &SSA[CSSA - 1]

        // Determine if exceptions were enabled
        "mov    r11,    [r10 + {EXTO}]      ",  // r11 = SSA[CSSA - 1].extra[0]
        "cmp    r11,    0                   ",  // If exceptions aren't enabled yet...
        "je     2b                          ",  // ... loop forever.

        // Find stack pointer for CSSA > 0
        "mov    r10,    [r10 + {RSPO}]      ",  // r10 = SSA[CSSA - 1].gpr.rsp
        "sub    r10,    128                 ",  // Skip the red zone

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
        "4:                                 ",  // rdi = &mut sallyport::Block (passthrough)
        "lea    rsi,    [rcx + 4096]        ",  // rsi = &mut [StateSaveArea; N]
        "mov    rdx,    rax                 ",  // rdx = CSSA
        "call   {CLEARX}                    ",  // Clear CPU state
        "call   {ENTRY}                     ",  // Jump to Rust
        "call   {CLEARX}                    ",  // Clear CPU state
        "call   {CLEARP}                    ",  // Clear parameter registers

        // Exit
        "pop    rsp                         ",  // Restore old stack
        "mov    rax,    {EEXIT}             ",  // rax = EEXIT
        "enclu                              ",  // Exit enclave

        // offset_of!(StateSaveArea, gpr.rsp)
        RSPO = const size_of::<StateSaveArea>() - size_of::<GenPurposeRegs>() + 32,

        // offset_of!(StateSaveArea, extra)
        EXTO = const size_of::<xsave::XSave>(),

        CLEARX = sym clearx,
        CLEARP = sym clearp,
        RELOC = sym relocate,
        ENTRY = sym main,
        EEXIT = const sgx::enclu::EEXIT,
        options(noreturn)
    )
}

unsafe extern "C" fn main(port: &mut sallyport::Block, ssas: &mut [StateSaveArea; 3], cssa: usize) {
    ssas[cssa].extra[0] = 1; // Enable exceptions

    match cssa {
        0 => entry::entry(&ENARX_EXEC_START as *const u8 as _),
        1 => handler::Handler::handle(&mut ssas[0], port),
        n => handler::Handler::finish(&mut ssas[n - 1]),
    }

    ssas[cssa].extra[0] = 0; // Disable exceptions
}
