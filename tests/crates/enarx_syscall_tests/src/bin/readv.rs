// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![feature(naked_functions)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    /* sizeof("hello, world") = 12 (note: no NUL byte) */
    let mut a = [0u8; 12];
    let mut b = [0u8; 12];
    let mut c = [0u8; 12];

    /* input = "hello, worldhello, worldhello, world"
     * so we'll gather each greeting into its own array */

    let iov: [libc::iovec; 3] = [
        libc::iovec {
            iov_base: a.as_mut_ptr() as _,
            iov_len: a.len(),
        },
        libc::iovec {
            iov_base: b.as_mut_ptr() as _,
            iov_len: b.len(),
        },
        libc::iovec {
            iov_base: c.as_mut_ptr() as _,
            iov_len: c.len(),
        },
    ];

    readv(libc::STDIN_FILENO, iov.as_ptr(), iov.len() as _)?;

    write(libc::STDOUT_FILENO, a.as_ptr(), a.len() as _)?;
    write(libc::STDOUT_FILENO, b.as_ptr(), b.len() as _)?;
    write(libc::STDOUT_FILENO, c.as_ptr(), c.len() as _)?;

    Ok(())
}
