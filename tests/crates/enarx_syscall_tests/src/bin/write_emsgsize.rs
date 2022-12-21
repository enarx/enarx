// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    let out = [b'A'; 128 * 1024];
    write(libc::STDOUT_FILENO, out.as_ptr(), out.len())?;
    Ok(())
}
