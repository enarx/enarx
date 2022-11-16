// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    let mut buf = [0u8; 16];
    let mut in_len = 1;

    loop {
        let out = read(libc::STDIN_FILENO, &mut buf as _, in_len)?;
        if out == 0 {
            break;
        }
        write(libc::STDOUT_FILENO, buf.as_ptr(), out as _)?;
        in_len = buf.len().min(in_len * 2);
    }
    Ok(())
}
