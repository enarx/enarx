// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![feature(asm_sym)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    close(libc::STDIN_FILENO)
}
