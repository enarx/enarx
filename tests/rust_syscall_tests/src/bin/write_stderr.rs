// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![feature(naked_functions, asm_sym)]

rust_syscall_tests::startup!();

use rust_syscall_tests::*;

fn main() -> Result<()> {
    let out = b"hi\n";
    let len = write(libc::STDERR_FILENO, out.as_ptr(), out.len())?;
    if len as usize == out.len() {
        Ok(())
    } else {
        Err(1)
    }
}
