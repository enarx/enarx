// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "wasmldr")]

use process_control::{ChildExt, Output, Timeout};
use std::fs::File;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

extern crate libc;
use libc::c_int;

use std::io;
use std::io::Write;
use std::time::Duration;

pub mod common;
use common::{check_output, CRATE, KEEP_BIN, OUT_DIR, TEST_BINS_OUT, TIMEOUT_SECS};

use serial_test::serial;

const MODULE_FD: RawFd = 3;

// wrap a libc call to return io::Result<c_int>
fn cvt(rv: c_int) -> io::Result<c_int> {
    if rv == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rv)
    }
}

// wrap a libc call to return io::Result<()>
fn cv(rv: c_int) -> io::Result<()> {
    cvt(rv).and(Ok(()))
}

trait CommandFdExt {
    fn inherit_with_fd(&mut self, file: impl IntoRawFd, child_fd: RawFd) -> &mut Self;
}

impl CommandFdExt for Command {
    fn inherit_with_fd(&mut self, file: impl IntoRawFd, child_fd: RawFd) -> &mut Self {
        let fd = file.into_raw_fd();
        if fd == child_fd {
            unsafe {
                self.pre_exec(move || cv(libc::fcntl(fd, libc::F_SETFD, 0)));
            }
        } else {
            unsafe {
                self.pre_exec(move || cv(libc::dup2(fd, child_fd)));
            }
        }
        self
    }
}

pub fn wasmldr_exec<'a>(wasm: &str, input: impl Into<Option<&'a [u8]>>) -> Output {
    let wasm_path = Path::new(CRATE)
        .join(OUT_DIR)
        .join(TEST_BINS_OUT)
        .join(wasm);
    let wasm_file =
        File::open(wasm_path).unwrap_or_else(|e| panic!("failed to open `{}`: {:#?}", wasm, e));

    let mut child = Command::new(&String::from(KEEP_BIN))
        .current_dir(CRATE)
        .arg("exec")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .inherit_with_fd(wasm_file, MODULE_FD)
        .spawn()
        .unwrap_or_else(|e| panic!("failed to run `{}`: {:#?}", wasm, e));

    if let Some(input) = input.into() {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input)
            .expect("failed to write stdin to child");

        drop(child.stdin.take());
    }

    let output = child
        .with_output_timeout(Duration::from_secs(TIMEOUT_SECS))
        .terminating()
        .wait()
        .unwrap_or_else(|e| panic!("failed to run `{}`: {:#?}", wasm, e))
        .unwrap_or_else(|| panic!("process `{}` timed out", wasm));

    assert!(
        output.status.code().is_some(),
        "process `{}` terminated by signal {:?}",
        wasm,
        output.status.signal()
    );

    output
}

fn run_wasm_test<'a>(
    wasm: &str,
    status: i32,
    input: impl Into<Option<&'a [u8]>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) -> Output {
    let output = wasmldr_exec(wasm, input);
    check_output(&output, status, expected_stdout, expected_stderr);
    output
}

#[test]
#[serial]
fn return_1() {
    // This module does, in fact, return 1. But function return values
    // are separate from setting the process exit status code, so
    // we still expect a return code of '0' here.
    run_wasm_test("return_1.wasm", 0, None, None, None);
}

#[test]
#[serial]
fn wasi_snapshot1() {
    // This module uses WASI to return the number of commandline args.
    // Since we don't currently do anything with the function return value,
    // we don't get any output here, and we expect '0', as above.
    run_wasm_test("wasi_snapshot1.wasm", 0, None, None, None);
}

#[test]
#[serial]
fn hello_wasi_snapshot1() {
    // This module just prints "Hello, world!" to stdout. Hooray!
    run_wasm_test(
        "hello_wasi_snapshot1.wasm",
        0,
        None,
        &b"Hello, world!\n"[..],
        None,
    );
}

#[test]
#[serial]
fn no_export() {
    // This module has no exported functions, so we get Error::ExportNotFound,
    // which wasmldr maps to EX_DATAERR (65) at process exit.
    run_wasm_test("no_export.wasm", 65, None, None, None);
}
