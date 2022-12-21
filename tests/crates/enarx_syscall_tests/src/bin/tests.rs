// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

enarx_syscall_tests::startup!();

use core::mem::size_of_val;
use core::mem::MaybeUninit;
use core::ptr::addr_of;
use enarx_syscall_tests::*;
use numtoa::NumToA;

const CLOCK_MONOTONIC: libc::clockid_t = 1;
const UNIX_ABSTRACT_PATH: &[u8; 34] = b"@enarx_listen_test0000000000000000";
const AF_UNIX: i32 = 1;
const AF_INET: i32 = 2;
const SOCK_DGRAM: i32 = 2;

fn test_uname() {
    const LINUX: [i8; 5] = ['L' as i8, 'i' as i8, 'n' as i8, 'u' as i8, 'x' as i8];
    let mut buf = libc::utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };

    uname(&mut buf as _).unwrap();

    assert!(buf.sysname.starts_with(&LINUX));
}

fn test_socket() {
    socket(AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0).unwrap();
    socket(AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0).unwrap();
    socket(AF_INET, SOCK_DGRAM | libc::SOCK_CLOEXEC, 0).unwrap();
}

fn test_clock_gettime() {
    let mut t = MaybeUninit::<libc::timespec>::uninit();
    clock_gettime(CLOCK_MONOTONIC, t.as_mut_ptr()).unwrap();
    let rax = write(libc::STDOUT_FILENO, t.as_mut_ptr() as _, size_of_val(&t)).unwrap();
    assert_eq!(rax as usize, size_of_val(&t));
}

fn test_listen() {
    let fd = socket(AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0).unwrap();

    // getpid() does not work, because it is returning 1 always
    let rand: u64 = random();

    let mut path: [u8; UNIX_ABSTRACT_PATH.len()] = *UNIX_ABSTRACT_PATH;

    rand.numtoa(16, &mut path[18..]);

    let mut sa = libc::sockaddr_un {
        sun_family: AF_UNIX as _,
        sun_path: [0; 108],
    };
    sa.sun_path[..path.len()].copy_from_slice(unsafe { core::mem::transmute(path.as_slice()) });
    sa.sun_path[0] = 0;

    let sa_len: libc::socklen_t = (UNIX_ABSTRACT_PATH.len()
        + (addr_of!(sa.sun_path) as usize - &sa as *const _ as usize))
        as _;

    bind(fd, &sa as *const _ as _, sa_len).unwrap();
    listen(fd, 0).unwrap();
}

fn test_close() {
    close(libc::STDIN_FILENO).unwrap();
}

fn test_egid() {
    if !is_enarx() {
        return;
    }
    assert_eq!(getegid().unwrap(), 1000);
}

fn test_euid() {
    if !is_enarx() {
        return;
    }
    assert_eq!(geteuid().unwrap(), 1000);
}

fn test_gid() {
    if !is_enarx() {
        return;
    }
    assert_eq!(getgid().unwrap(), 1000);
}

fn test_uid() {
    if !is_enarx() {
        return;
    }
    assert_eq!(getuid().unwrap(), 1000);
}

fn main() -> Result<()> {
    test_uname();
    test_clock_gettime();
    test_euid();
    test_egid();
    test_uid();
    test_gid();
    test_socket();
    test_listen();
    test_close();
    Ok(())
}
