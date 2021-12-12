// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "wasmldr")]
#![cfg(not(feature = "gdb"))]

use process_control::{ChildExt, Output, Timeout};

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub mod common;
use common::{check_output, CRATE, KEEP_BIN, OUT_DIR, TEST_BINS_OUT, TIMEOUT_SECS};

fn create(path: &Path) {
    match std::fs::create_dir(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            eprintln!("Can't create {:#?} : {:#?}", path, e);
            std::process::exit(1);
        }
        Ok(_) => {}
    }
}

pub fn enarx_run<'a>(wasm: &str, input: impl Into<Option<&'a [u8]>>) -> Output {
    let wasm_path = Path::new(CRATE)
        .join(OUT_DIR)
        .join(TEST_BINS_OUT)
        .join(wasm);

    let mut child = Command::new(&String::from(KEEP_BIN))
        .current_dir(CRATE)
        .arg("run")
        .arg(wasm_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

fn compile(wasm: &str) {
    let out_dir = Path::new(CRATE).join(OUT_DIR).join(TEST_BINS_OUT);
    let wasm = out_dir.join(wasm);

    create(&out_dir);

    let src_path = &Path::new(CRATE).join("tests/wasm");

    let wat = src_path
        .join(wasm.file_stem().unwrap())
        .with_extension("wat");

    // poor mans `make`
    if wasm.exists() {
        let wasm_meta = wasm.metadata().unwrap();
        let wasm_time = wasm_meta.modified().unwrap();

        let wat_meta = wat.metadata().unwrap();
        let wat_time = wat_meta.modified().unwrap();

        if wasm_meta.len() > 0 && wasm_time > wat_time {
            // skip, if already compiled and newer than original
            return;
        }
    }

    let bin = wat::parse_file(&wat).unwrap_or_else(|_| panic!("failed to compile {:?}", &wat));
    std::fs::write(&wasm, &bin).unwrap_or_else(|_| panic!("failed to write {:?}", &wasm));
}

fn run_wasm_test<'a>(
    wasm: &str,
    status: i32,
    input: impl Into<Option<&'a [u8]>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) -> Output {
    compile(wasm);

    let output = enarx_run(wasm, input);
    check_output(&output, status, expected_stdout, expected_stderr);
    output
}

#[test]
fn return_1() {
    // This module does, in fact, return 1. But function return values
    // are separate from setting the process exit status code, so
    // we still expect a return code of '0' here.
    run_wasm_test("return_1.wasm", 0, None, None, None);
}

#[test]
fn wasi_snapshot1() {
    // This module uses WASI to return the number of commandline args.
    // Since we don't currently do anything with the function return value,
    // we don't get any output here, and we expect '0', as above.
    run_wasm_test("wasi_snapshot1.wasm", 0, None, None, None);
}

#[test]
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
fn no_export() {
    // This module has no exported functions, so we get Error::ExportNotFound,
    // which wasmldr maps to EX_DATAERR (65) at process exit.
    run_wasm_test("no_export.wasm", 65, None, None, None);
}
