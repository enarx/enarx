// SPDX-License-Identifier: Apache-2.0
#![cfg(not(miri))]
#![cfg(not(feature = "gdb"))]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

use serial_test::serial;
use std::sync::Arc;
use tempfile::Builder;

mod common;
use common::{assert_eq_slices, run_crate};

#[test]
#[serial]
fn echo() {
    let mut input: Vec<u8> = Vec::with_capacity(2 * 1024 * 1024);

    for i in 0..input.capacity() {
        input.push(i as _);
    }

    let expected_input = input.clone();

    run_crate(
        "tests/rust-exec",
        "echo",
        None,
        0,
        input,
        expected_input.as_slice(),
        None,
    );
}

#[test]
// FIXME: this tests causes frequent failure on SEV
#[ignore]
#[serial]
fn unix_echo() {
    let tmpdir = Arc::new(Builder::new().prefix("unix_echo").tempdir().unwrap());
    const FILENAME_IN: &str = "enarx_unix_echo_to_bin";
    const FILENAME_OUT: &str = "enarx_unix_echo_from_bin";
    let mut input: Vec<u8> = Vec::with_capacity(2 * 1024 * 1024);

    let _ = fs::remove_file(FILENAME_IN);

    for i in 0..input.capacity() {
        input.push(i as _);
    }

    let handle = thread::spawn({
        let tmpdir = tmpdir.clone();
        move || {
            let socket_path = tmpdir.path().join(FILENAME_IN);
            let mut cnt = 0;
            while cnt < 100 && !socket_path.exists() {
                cnt += 1;
                thread::sleep(Duration::from_millis(500))
            }
            if socket_path.exists() {
                let listener = UnixListener::bind(tmpdir.path().join(FILENAME_OUT)).unwrap();

                let mut socket = UnixStream::connect(tmpdir.path().join(FILENAME_IN)).unwrap();
                socket.write_all(&input).unwrap();
                // close the socket to let the test get EOF
                drop(socket);

                let (mut socket, _) = listener.accept().unwrap();

                let mut buffer = Vec::new();
                socket.read_to_end(&mut buffer).unwrap();

                assert_eq_slices(&input, &buffer, "stream output");
            }
        }
    });

    run_crate(
        "tests/rust-exec",
        "unix_echo",
        None,
        0,
        Vec::from(tmpdir.path().as_os_str().as_bytes()),
        None,
        None,
    );

    handle.join().unwrap();
}

#[cfg(feature = "backend-sev")]
#[test]
#[cfg_attr(not(host_can_test_sev), ignore)]
#[serial]
fn rust_sev_attestation() {
    run_crate(
        "tests/sev_attestation",
        "sev_attestation",
        None,
        0,
        None,
        None,
        None,
    );
}

#[test]
#[serial]
fn memspike() {
    run_crate("tests/rust-exec", "memspike", None, 0, None, None, None);
}

#[test]
#[serial]
fn memory_stress_test() {
    run_crate(
        "tests/rust-exec",
        "memory_stress_test",
        None,
        0,
        None,
        None,
        None,
    );
}

#[test]
#[serial]
fn cpuid() {
    run_crate("tests/rust-exec", "cpuid", None, 0, None, None, None);
}
