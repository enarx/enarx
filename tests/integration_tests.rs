// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::mem::{size_of, MaybeUninit};
use std::path::Path;
use std::process::{Command, Stdio};
use std::slice::from_raw_parts_mut;
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

fn read_item<T: Copy>(mut rdr: impl Read) -> std::io::Result<T> {
    let mut item = MaybeUninit::uninit();
    let ptr = item.as_mut_ptr() as *mut u8;
    let buf = unsafe { from_raw_parts_mut(ptr, size_of::<T>()) };
    rdr.read_exact(buf)?;
    Ok(unsafe { item.assume_init() })
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
    let child = run_test("write_stdout", 0);
    let stdout = child.stdout.unwrap();

    let buf: [u8; 3] = read_item(stdout).unwrap();
    assert_eq!("hi\n", String::from_utf8(buf.to_vec()).unwrap());
}

#[test]
fn write_stderr() {
    let child = run_test("write_stderr", 0);
    let stdout = child.stderr.unwrap();

    let buf: [u8; 3] = read_item(stdout).unwrap();
    assert_eq!("hi\n", String::from_utf8(buf.to_vec()).unwrap());
}
