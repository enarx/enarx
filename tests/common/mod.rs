// SPDX-License-Identifier: Apache-2.0

use process_control::{ChildExt, Output, Timeout};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const CRATE: &str = env!("CARGO_MANIFEST_DIR");
pub const KEEP_BIN: &str = env!("CARGO_BIN_EXE_enarx");
pub const OUT_DIR: &str = env!("OUT_DIR");
pub const TEST_BINS_OUT: &str = "bin";
pub const TIMEOUT_SECS: u64 = 30;
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
        .with_output_timeout(Duration::from_secs(TIMEOUT_SECS))
        .terminating()
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
    check_output(&output, status.into(), expected_stdout, expected_stderr);
    output
}
