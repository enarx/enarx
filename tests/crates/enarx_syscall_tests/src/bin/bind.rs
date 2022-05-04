// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![feature(naked_functions, asm_sym)]

enarx_syscall_tests::startup!();

use core::ptr::addr_of;
use enarx_syscall_tests::*;

const UNIX_ABSTRACT_PATH: &str = "@enarx_bind_test";
const AF_UNIX: i32 = 1;

fn main() -> Result<()> {
    let fd = socket(AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)?;

    let mut sa = libc::sockaddr_un {
        sun_family: AF_UNIX as _,
        sun_path: [0; 108],
    };
    sa.sun_path[..UNIX_ABSTRACT_PATH.len()]
        .copy_from_slice(unsafe { core::mem::transmute(UNIX_ABSTRACT_PATH.as_bytes()) });
    sa.sun_path[0] = 0;

    let sa_len: libc::socklen_t = (UNIX_ABSTRACT_PATH.len()
        + (addr_of!(sa.sun_path) as usize - &sa as *const _ as usize))
        as _;

    bind(fd, &sa as *const _ as _, sa_len)?;
    Ok(())
}
