// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::mem::{size_of, MaybeUninit};
use std::path::Path;
use std::process::{Command, Stdio};
use std::slice::from_raw_parts_mut;
use std::time::Duration;

use process_control::{ChildExt, Output, Timeout};
use serial_test::serial;

const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const KEEP_BIN: &str = env!("CARGO_BIN_EXE_enarx-keepldr");
const OUT_DIR: &str = env!("OUT_DIR");
const TEST_BINS_OUT: &str = "bin";
const TIMEOUT_SECS: u64 = 10;

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
fn run_test<'a>(
    bin: &str,
    status: i32,
    input: impl Into<Option<&'a [u8]>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) -> Output {
    let bin_path = Path::new(CRATE).join(OUT_DIR).join(TEST_BINS_OUT).join(bin);

    let mut child = Command::new(&String::from(KEEP_BIN))
        .current_dir(CRATE)
        .arg("exec")
        .arg(bin_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to run `{}`: {:#?}", bin, e));

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
        .unwrap_or_else(|e| panic!("failed to run `{}`: {:#?}", bin, e))
        .unwrap_or_else(|| panic!("process `{}` timed out", bin));

    let exit_status = output.status.code().unwrap_or_else(|| {
        panic!(
            "process `{}` terminated by signal {:?}",
            bin,
            output.status.signal()
        )
    });

    if let Some(expected_stdout) = expected_stdout.into() {
        assert!(output.stdout.eq(expected_stdout));
    }

    if let Some(expected_stderr) = expected_stderr.into() {
        assert!(output.stderr.eq(expected_stderr));
    }

    if exit_status != status as i64 {
        std::io::stderr()
            .write_all(output.stderr.as_slice())
            .unwrap();
        assert_eq!(exit_status, status as i64);
    }

    output
}

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
    run_test("exit_zero", 0, None, None, None);
}

#[test]
#[serial]
fn exit_one() {
    run_test("exit_one", 1, None, None, None);
}

#[test]
#[serial]
fn clock_gettime() {
    use libc::{clock_gettime, CLOCK_MONOTONIC};

    // Get the time from inside the keep.
    let stdout = run_test("clock_gettime", 0, None, None, None).stdout;
    let theirs: libc::timespec = read_item(stdout.as_slice()).unwrap();

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
#[serial]
fn write_stdout() {
    run_test("write_stdout", 0, None, &b"hi\n"[..], None);
}

#[test]
#[serial]
fn write_stderr() {
    run_test("write_stderr", 0, None, None, &b"hi\n"[..]);
}

#[test]
#[serial]
// FIXME this should not be ignored, this was applied as part
// of a commit that must be reverted and implemented properly.
#[ignore]
fn write_emsgsize() {
    run_test("write_emsgsize", 0, None, None, None);
}

#[test]
#[serial]
fn read() {
    const INPUT: &[u8; 12] = b"hello world\n";
    run_test("read", 0, &INPUT[..], &INPUT[..], None);
}

#[test]
#[serial]
fn readv() {
    const INPUT: &[u8; 36] = b"hello, worldhello, worldhello, world";
    run_test("readv", 0, &INPUT[..], &INPUT[..], None);
}

#[test]
#[serial]
fn echo() {
    let mut input: Vec<u8> = Vec::with_capacity(4096);
    for i in 0..input.capacity() {
        input.push(i as _);
    }
    run_test("echo", 0, input.as_slice(), input.as_slice(), None);
}

#[test]
#[serial]
fn get_att() {
    run_test("get_att", 0, None, None, None);
}

#[test]
#[serial]
fn getuid() {
    run_test("getuid", 0, None, None, None);
}

#[test]
#[serial]
fn geteuid() {
    run_test("geteuid", 0, None, None, None);
}

#[test]
#[serial]
fn getgid() {
    run_test("getgid", 0, None, None, None);
}

#[test]
#[serial]
fn getegid() {
    run_test("getegid", 0, None, None, None);
}
