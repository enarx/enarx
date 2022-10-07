// SPDX-License-Identifier: Apache-2.0

// Read and write a buffer of the size of a maximum sized UDP packet
// in one go and fail, if it was fragmented.

#![no_std]
#![no_main]
#![feature(asm_sym)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    let mut buf = [0u8; 65507];
    let out = read(libc::STDIN_FILENO, &mut buf as _, buf.len())? as usize;
    if out != buf.len() {
        return Err(1);
    }

    let out = write(libc::STDOUT_FILENO, buf.as_ptr(), out as _)? as usize;
    if out != buf.len() {
        return Err(1);
    }

    Ok(())
}
