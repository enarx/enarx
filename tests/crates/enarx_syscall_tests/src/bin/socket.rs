// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![feature(naked_functions, asm_sym)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

const AF_UNIX: i32 = 1;
const AF_INET: i32 = 2;
const SOCK_DGRAM: i32 = 2;

fn main() -> Result<()> {
    socket(AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)?;
    socket(AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)?;
    socket(AF_INET, SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)?;
    Ok(())
}
