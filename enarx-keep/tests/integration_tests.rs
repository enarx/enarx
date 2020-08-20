// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const KEEP_BIN: &str = env!("CARGO_BIN_EXE_enarx-keep");
const OUT_DIR: &str = env!("OUT_DIR");
const TEST_BINS_OUT: &str = "bin";
const TIMEOUT_SECS: u64 = 5;

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
fn run_test(bin: &str, status: i32) -> std::process::Child {
    let bin = Path::new(CRATE).join(OUT_DIR).join(TEST_BINS_OUT).join(bin);

    let mut child = Command::new(&String::from(KEEP_BIN))
        .current_dir(CRATE)
        .arg("exec")
        .arg(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run test bin");

    let code = match child
        .wait_timeout(Duration::from_secs(TIMEOUT_SECS))
        .unwrap()
    {
        Some(status) => status.code().unwrap(),
        None => {
            child.kill().unwrap();
            panic!("error: test timeout");
        }
    };

    assert_eq!(code, status);
    child
}

#[test]
fn exit_zero() {
    run_test("exit_zero", 0);
}

#[test]
fn exit_one() {
    run_test("exit_one", 1);
}

#[test]
fn clock_gettime() {
    run_test("clock_gettime", 0);
}

#[test]
fn write_stdout() {
    let mut buf = [0u8; 3];
    let child = run_test("write_stdout", 0);
    child
        .stdout
        .unwrap()
        .read(&mut buf)
        .expect("failed to read child stdout");
    assert_eq!("hi\n", String::from_utf8(buf.to_vec()).unwrap());
}

#[test]
fn write_stderr() {
    let mut buf = [0u8; 3];
    let child = run_test("write_stderr", 0);
    child
        .stderr
        .unwrap()
        .read(&mut buf)
        .expect("failed to read child stderr");
    assert_eq!("hi\n", String::from_utf8(buf.to_vec()).unwrap());
}
