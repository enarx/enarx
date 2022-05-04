// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![feature(naked_functions, asm_sym)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    let out = [b'A'; 128 * 1024];
    write(libc::STDOUT_FILENO, out.as_ptr(), out.len())?;
    Ok(())
}
