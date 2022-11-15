// SPDX-License-Identifier: Apache-2.0

use super::{is_nil, is_sgx, run_test};

use std::io::Read;
use std::mem::{size_of, MaybeUninit};
use std::slice::from_raw_parts_mut;

use serial_test::serial;

fn read_item<T: Copy>(mut rdr: impl Read) -> std::io::Result<T> {
    let mut item = MaybeUninit::uninit();
    let ptr = item.as_mut_ptr() as *mut u8;
    let buf = unsafe { from_raw_parts_mut(ptr, size_of::<T>()) };
    rdr.read_exact(buf)?;
    Ok(unsafe { item.assume_init() })
}

#[test]
#[serial]
fn exit_zero() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_exit_zero");
    run_test(bin, 0, None, None, None);
}

#[test]
#[serial]
fn exit_one() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_exit_one");
    run_test(bin, 1, None, None, None);
}

#[test]
#[serial]
fn write_stdout() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_write_stdout");
    run_test(bin, 0, None, &b"hi\n"[..], None);
}

#[cfg(not(feature = "dbg"))]
#[test]
#[serial]
fn write_stderr() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_write_stderr");
    run_test(bin, 0, None, None, &b"hi\n"[..]);
}

#[test]
#[serial]
fn write_emsgsize() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_write_emsgsize");
    run_test(bin, 0, None, None, None);
}

#[test]
#[serial]
fn read() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    const INPUT: &[u8; 12] = b"hello world\n";
    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_read");
    run_test(bin, 0, INPUT.as_slice(), INPUT.as_slice(), None);
}

#[test]
#[serial]
fn readv() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    const INPUT: &[u8; 36] = b"hello, worldhello, worldhello, world";
    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_readv");
    run_test(bin, 0, INPUT.as_slice(), INPUT.as_slice(), None);
}

#[test]
#[serial]
fn read_udp() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    // The maximum UDP message size is 65507, as determined by the following formula:
    // 0xffff - (sizeof(minimal IP Header) + sizeof(UDP Header)) = 65535-(20+8) = 65507
    const MAX_UDP_PACKET_SIZE: usize = 65507;

    let mut input: Vec<u8> = Vec::with_capacity(MAX_UDP_PACKET_SIZE);
    for i in 0..input.capacity() {
        input.push(i as _);
    }
    let input = input.as_slice();

    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_read_udp");
    run_test(bin, 0, input, input, None);
}

#[cfg_attr(
    not(host_can_test_attestation),
    ignore = "Backend does not support attestation"
)]
#[test]
#[serial]
fn get_att() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_get_att");
    run_test(bin, 0, None, None, None);
}

#[cfg_attr(
    any(not(host_can_test_sgx), not(host_can_test_attestation)),
    ignore = "Backend does not support SGX"
)]
#[test]
#[serial]
fn sgx_get_att_quote() {
    if !is_sgx() {
        eprintln!("SGX backend is disabled, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_sgx_get_att_quote");
    run_test(bin, 0, None, None, None);
}

#[test]
#[serial]
fn tests() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    use libc::{clock_gettime, CLOCK_MONOTONIC};

    // Get the time from inside the keep.
    let bin = env!("CARGO_BIN_FILE_ENARX_SYSCALL_TESTS_tests");
    let stdout = run_test(bin, 0, None, None, None).stdout;
    let theirs: libc::timespec = read_item(stdout.as_slice()).unwrap();

    // Get the time from outside the keep.
    let ours = unsafe {
        let mut ts = MaybeUninit::uninit();
        assert_eq!(0, clock_gettime(CLOCK_MONOTONIC, ts.as_mut_ptr()));
        ts.assume_init()
    };

    // Validate that the difference in time is minor...
    const NSEC_PER_SEC: libc::c_long = 1_000_000_000;
    const MAX_SEC: libc::c_long = 60;

    let sec = ours.tv_sec - theirs.tv_sec;
    assert!(sec >= 0);
    assert!(sec < MAX_SEC);

    let nsec = sec * NSEC_PER_SEC + ours.tv_nsec - theirs.tv_nsec;
    assert!(nsec >= 0);
    assert!(nsec < MAX_SEC * NSEC_PER_SEC);
}
