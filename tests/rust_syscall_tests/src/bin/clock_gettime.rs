// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![feature(naked_functions, asm_sym)]

rust_syscall_tests::startup!();

use core::mem::size_of_val;
use core::mem::MaybeUninit;
use rust_syscall_tests::*;
pub const CLOCK_MONOTONIC: libc::clockid_t = 1;

fn main() -> Result<()> {
    let mut t = MaybeUninit::<libc::timespec>::uninit();
    clock_gettime(CLOCK_MONOTONIC, t.as_mut_ptr())?;
    let rax = write(libc::STDOUT_FILENO, t.as_mut_ptr() as _, size_of_val(&t))?;

    if rax as usize == size_of_val(&t) {
        Ok(())
    } else {
        Err(1)
    }
}
