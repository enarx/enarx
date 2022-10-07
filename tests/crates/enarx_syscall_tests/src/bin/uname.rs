// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![feature(asm_sym)]

enarx_syscall_tests::startup!();

use enarx_syscall_tests::*;

fn main() -> Result<()> {
    const LINUX: [i8; 5] = ['L' as i8, 'i' as i8, 'n' as i8, 'u' as i8, 'x' as i8];
    let mut buf = libc::utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };

    uname(&mut buf as _)?;

    if !buf.sysname.starts_with(&LINUX) {
        Err(1)
    } else {
        Ok(())
    }
}
