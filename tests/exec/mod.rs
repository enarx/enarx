// SPDX-License-Identifier: Apache-2.0

use super::{assert_eq_slices, enarx, is_nil, is_sev, is_sgx, run_test, run_test_signed};

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

use std::sync::Arc;
use tempfile::Builder;

#[test]
fn futex() {
    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_futex");

    run_test(bin, 0, None, None, None);
}

#[test]
#[cfg_attr(not(host_can_test_sgx), ignore = "Backend does not support SGX")]
fn thread() {
    if !is_sgx() {
        eprintln!("SGX backend is disabled, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_thread");
    let output = r#"Before Spawn
After Spawn 1
After Spawn 2
Hello from Thread 2!
Hello from Thread 1!
After Join 1
After Join 2
Before Spawn
After Spawn 1
After Spawn 2
Hello from Thread 2!
Hello from Thread 1!
After Join 1
After Join 2
"#;
    run_test(bin, 0, None, output.as_bytes(), None);
}

#[test]
#[cfg_attr(not(host_can_test_sgx), ignore = "Backend does not support SGX")]
fn thread_many() {
    if !is_sgx() {
        eprintln!("SGX backend is disabled, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_thread-many");
    run_test(bin, 0, None, None, None);
}

#[test]
#[cfg_attr(not(host_can_test_sgx), ignore = "Backend does not support SGX")]
fn thread_exit_group() {
    if !is_sgx() {
        eprintln!("SGX backend is disabled, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_thread-exit-group");
    run_test(bin, 0, None, None, None);
}

#[test]
#[cfg_attr(not(host_can_test_sgx), ignore = "Backend does not support SGX")]
fn thread_channel() {
    if !is_sgx() {
        eprintln!("SGX backend is disabled, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_thread-channel");
    let output = "Start\nHello, thread\n";
    run_test(bin, 0, None, output.as_bytes(), None);
}

#[test]
fn echo() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let mut input: Vec<u8> = Vec::with_capacity(2 * 1024 * 1024);

    for i in 0..input.capacity() {
        input.push(i as _);
    }
    let input = input.as_slice();

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_echo");
    run_test(bin, 0, input, input, None);
}

#[test]
fn unix_echo() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

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

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_unix_echo");
    let input = tmpdir.path().as_os_str().as_bytes();
    run_test(bin, 0, input, None, None);

    handle.join().unwrap();
}

#[test]
#[cfg_attr(not(host_can_test_sev), ignore = "Backend does not support SEV-SNP")]
fn rust_sev_attestation() {
    if !is_sev() {
        eprintln!("SEV backend is disabled, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_sev_attestation");
    let mut exp_out = vec![];
    exp_out.extend_from_slice(b"ID_KEY_DIGEST = ".as_slice());
    exp_out.extend_from_slice(
        enarx(
            |cmd| {
                cmd.args(vec![
                    OsStr::new("key"),
                    OsStr::new("sev"),
                    OsStr::new("digest"),
                    OsStr::new("tests/data/sev-id.key"),
                ])
            },
            None,
        )
        .stdout
        .as_slice(),
    );
    exp_out.push(b'\n');
    exp_out.extend_from_slice(b"AUTHOR_KEY_DIGEST = ".as_slice());
    exp_out.extend_from_slice(
        enarx(
            |cmd| {
                cmd.args(vec![
                    OsStr::new("key"),
                    OsStr::new("sev"),
                    OsStr::new("digest"),
                    OsStr::new("tests/data/sev-author.key"),
                ])
            },
            None,
        )
        .stdout
        .as_slice(),
    );
    exp_out.push(b'\n');

    run_test_signed(bin, 0, None, exp_out.as_slice(), None);
}

#[test]
#[cfg_attr(not(host_can_test_sgx), ignore = "Backend does not support SGX")]
fn rust_sgx_attestation() {
    if !is_sgx() {
        eprintln!("SGX backend is disabled, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_sgx_attestation");
    let exp_out = b"MRSIGNER = 298037d88782e022e019b3020745b78aa40ed95c77da4bf7f3253d3a44c4fd7e\n";
    run_test_signed(bin, 0, None, exp_out.as_slice(), None);
}

#[test]
fn memspike() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_memspike");
    run_test(bin, 0, None, None, None);
}

#[test]
fn memory_stress_test() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_memory_stress_test");
    run_test(bin, 0, None, None, None);
}

#[test]
fn cpuid() {
    if is_nil() {
        eprintln!("Not supported on nil backend, ignoring");
        return;
    }

    let bin = env!("CARGO_BIN_FILE_ENARX_EXEC_TESTS_cpuid");
    run_test(bin, 0, None, None, None);
}
