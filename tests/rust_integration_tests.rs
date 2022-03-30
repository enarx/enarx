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
use common::{assert_eq_slices, run_test};

#[test]
#[serial]
fn echo() {
    let mut input: Vec<u8> = Vec::with_capacity(2 * 1024 * 1024);

    for i in 0..input.capacity() {
        input.push(i as _);
    }
    let input = input.as_slice();

    let bin = env!("CARGO_BIN_FILE_RUST_EXEC_TESTS_echo");
    run_test(bin, 0, input, input, None);
}

#[test]
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

    let bin = env!("CARGO_BIN_FILE_RUST_EXEC_TESTS_unix_echo");
    let input = tmpdir.path().as_os_str().as_bytes();
    run_test(bin, 0, input, None, None);

    handle.join().unwrap();
}

#[cfg(feature = "backend-sev")]
#[test]
#[cfg_attr(not(host_can_test_sev), ignore)]
#[serial]
fn rust_sev_attestation() {
    let bin = env!("CARGO_BIN_FILE_SEV_ATTESTATION_sev_attestation");
    run_test(bin, 0, None, None, None);
}

#[test]
#[serial]
fn memspike() {
    let bin = env!("CARGO_BIN_FILE_RUST_EXEC_TESTS_memspike");
    run_test(bin, 0, None, None, None);
}

#[test]
#[serial]
fn memory_stress_test() {
    let bin = env!("CARGO_BIN_FILE_RUST_EXEC_TESTS_memory_stress_test");
    run_test(bin, 0, None, None, None);
}

#[test]
#[serial]
fn cpuid() {
    let bin = env!("CARGO_BIN_FILE_RUST_EXEC_TESTS_cpuid");
    run_test(bin, 0, None, None, None);
}
