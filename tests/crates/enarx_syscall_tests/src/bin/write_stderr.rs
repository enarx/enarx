// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    let out = b"hi\n";
    let len = write(libc::STDERR_FILENO, out.as_ptr(), out.len())?;
    if len as usize == out.len() {
        Ok(())
    } else {
        Err(1)
    }
}
