// SPDX-License-Identifier: Apache-2.0

//! syscall interface layer between assembler and rust

extern "C" {
    pub fn _syscall_enter() -> !;
}

#[allow(clippy::many_single_char_names)]
#[no_mangle]
/// Handle a syscall in rust
pub extern "C" fn syscall_rust(
    _a: usize,
    _b: usize,
    _c: usize,
    _d: usize,
    _e: usize,
    _f: usize,
    _nr: usize,
) -> usize {
    todo!();
}
