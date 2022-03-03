// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use process_control::{ChildExt, Control, Output};
use std::io::{stderr, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const CRATE: &str = env!("CARGO_MANIFEST_DIR");
pub const KEEP_BIN: &str = env!("CARGO_BIN_EXE_enarx");
pub const OUT_DIR: &str = env!("OUT_DIR");
pub const TEST_BINS_OUT: &str = "bin";
pub const TIMEOUT_SECS: u64 = 60 * 60;
pub const MAX_ASSERT_ELEMENTS: usize = 100;

pub fn assert_eq_slices(expected_output: &[u8], output: &[u8], what: &str) {
    let max_len = usize::min(output.len(), expected_output.len());
    let max_len = max_len.min(MAX_ASSERT_ELEMENTS);
    assert_eq!(
        output[..max_len],
        expected_output[..max_len],
        "Expected contents of {} differs",
        what
    );
    assert_eq!(
        output.len(),
        expected_output.len(),
        "Expected length of {} differs",
        what
    );
    assert_eq!(
        output, expected_output,
        "Expected contents of {} differs",
        what
    );
}

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
pub fn keepldr_exec<'a>(bin: &str, input: impl Into<Option<&'a [u8]>>) -> Output {
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
        .controlled_with_output()
        .time_limit(Duration::from_secs(TIMEOUT_SECS))
        .terminate_for_timeout()
        .wait()
        .unwrap_or_else(|e| panic!("failed to run `{}`: {:#?}", bin, e))
        .unwrap_or_else(|| panic!("process `{}` timed out", bin));

    assert!(
        output.status.code().is_some(),
        "process `{}` terminated by signal {:?}",
        bin,
        output.status.signal()
    );

    output
}

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
pub fn keepldr_exec_crate<'a>(
    crate_name: &str,
    bin: &str,
    bin_args: impl Into<Option<&'a [&'a str]>>,
    input: impl Into<Option<Vec<u8>>>,
) -> Output {
    let crate_path = Path::new(CRATE).join(crate_name);
    let bin_args = bin_args.into();

    let mut child = Command::new("cargo");

    let mut child = child
        .current_dir(crate_path)
        .arg("run")
        .arg("--quiet")
        .arg("--bin")
        .arg(bin)
        .env("ENARX_BIN", KEEP_BIN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(args) = bin_args {
        child = child.arg("--").args(args);
    }

    let mut child = child
        .spawn()
        .unwrap_or_else(|e| panic!("failed to run `{}`: {:#?}", bin, e));

    let input_thread = if let Some(input) = input.into() {
        let mut stdin = child.stdin.take().unwrap();
        let input = input.clone();
        Some(std::thread::spawn(move || {
            stdin
                .write_all(&input)
                .expect("failed to write stdin to child");
        }))
    } else {
        None
    };

    let output = child
        .controlled_with_output()
        .time_limit(Duration::from_secs(TIMEOUT_SECS))
        .terminate_for_timeout()
        .wait()
        .unwrap_or_else(|e| panic!("failed to run `{}`: {:#?}", bin, e))
        .unwrap_or_else(|| panic!("process `{}` timed out", bin));

    if let Some(input_thread) = input_thread {
        if let Err(_) = input_thread.join() {
            let _unused = stderr().write_all(&output.stderr);
            panic!("failed to provide input for process `{}`", bin)
        }
    }

    assert!(
        output.status.code().is_some(),
        "process `{}` terminated by signal {:?}",
        bin,
        output.status.signal()
    );

    output
}

pub fn check_output<'a>(
    output: &Output,
    expected_status: i32,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) {
    let expected_stdout = expected_stdout.into();
    let expected_stderr = expected_stderr.into();

    // Output potential error messages
    if expected_stderr.is_none() && !output.stderr.is_empty() {
        let _ = std::io::stderr().write_all(&output.stderr);
    }

    if let Some(expected_stdout) = expected_stdout {
        if output.stdout.len() < MAX_ASSERT_ELEMENTS && expected_stdout.len() < MAX_ASSERT_ELEMENTS
        {
            assert_eq!(
                output.stdout, expected_stdout,
                "Expected contents of stdout output differs"
            );
        } else {
            assert_eq_slices(expected_stdout, &output.stdout, "stdout output");
        }
    }

    if let Some(expected_stderr) = expected_stderr {
        if output.stderr.len() < MAX_ASSERT_ELEMENTS && expected_stderr.len() < MAX_ASSERT_ELEMENTS
        {
            assert_eq!(
                output.stderr, expected_stderr,
                "Expected contents of stderr output differs."
            );
        } else {
            assert_eq_slices(expected_stderr, &output.stderr, "stderr output");
        }
    }

    assert_eq!(
        output.status.code().unwrap(),
        expected_status as i64,
        "Expected exit status differs."
    );
}

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
pub fn run_test<'a>(
    bin: &str,
    status: i32,
    input: impl Into<Option<&'a [u8]>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) -> Output {
    let output = keepldr_exec(bin, input);
    check_output(&output, status, expected_stdout, expected_stderr);
    output
}

/// Returns a handle to a child process through which output (stdout, stderr) can
/// be accessed.
pub fn run_crate<'a>(
    crate_name: &str,
    bin: &str,
    bin_args: impl Into<Option<&'a [&'a str]>>,
    status: i32,
    input: impl Into<Option<Vec<u8>>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) -> Output {
    let output = keepldr_exec_crate(crate_name, bin, bin_args, input);
    check_output(&output, status, expected_stdout, expected_stderr);
    output
}
