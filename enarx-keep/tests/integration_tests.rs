// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
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
fn run_test<'a>(bin: &str, status: i32, input: impl Into<Option<&'a str>>) -> std::process::Child {
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

    if let Some(input) = input.into() {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.to_string().as_ref())
            .expect("failed to write stdin to child");

        drop(child.stdin.take());
    }

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
    run_test("exit_zero", 0, None);
}

#[test]
fn exit_one() {
    run_test("exit_one", 1, None);
}

#[test]
fn clock_gettime() {
    use libc::{clock_gettime, CLOCK_MONOTONIC};

    // Get the time from inside the keep.
    let stdout = run_test("clock_gettime", 0, None).stdout.unwrap();
    let theirs: libc::timespec = read_item(stdout).unwrap();

    // Get the time from outside the keep.
    let ours = unsafe {
        let mut ts = MaybeUninit::uninit();
        assert_eq!(0, clock_gettime(CLOCK_MONOTONIC, ts.as_mut_ptr()));
        ts.assume_init()
    };

    // Validate that the difference in time is minor...
    const NSEC_PER_SEC: libc::c_long = 1_000_000_000;
    const MAX_SEC: libc::c_long = 2;

    let sec = ours.tv_sec - theirs.tv_sec;
    assert!(sec >= 0);
    assert!(sec < MAX_SEC);

    let nsec = sec * NSEC_PER_SEC + ours.tv_nsec - theirs.tv_nsec;
    assert!(nsec >= 0);
    assert!(nsec < MAX_SEC * NSEC_PER_SEC);
}

#[test]
fn write_stdout() {
    let child = run_test("write_stdout", 0, None);
    let stdout = child.stdout.unwrap();

    let buf: [u8; 3] = read_item(stdout).unwrap();
    assert_eq!("hi\n", String::from_utf8(buf.to_vec()).unwrap());
}

#[test]
fn write_stderr() {
    let child = run_test("write_stderr", 0, None);
    let stdout = child.stderr.unwrap();

    let buf: [u8; 3] = read_item(stdout).unwrap();
    assert_eq!("hi\n", String::from_utf8(buf.to_vec()).unwrap());
}

#[test]
fn write_emsgsize() {
    run_test("write_emsgsize", 0, None);
}

#[test]
fn read() {
    const INPUT: &str = "hello world\n";
    const BYTES: usize = INPUT.as_bytes().len();
    let child = run_test("read", 0, INPUT);
    let stdout = child.stdout.unwrap();

    let buf: [u8; BYTES] = read_item(stdout).unwrap();
    assert_eq!(INPUT, String::from_utf8(buf.to_vec()).unwrap());
}
