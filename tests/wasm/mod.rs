// SPDX-License-Identifier: Apache-2.0

use super::{check_output, CRATE, KEEP_BIN, OUT_DIR, TEST_BINS_OUT, TIMEOUT_SECS};

use process_control::{ChildExt, Control, Output};
use serial_test::serial;
use tempfile::tempdir;
use url::Url;

use std::io::{stderr, Read, Write};
use std::net::{self, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time;
use std::{fs, thread};

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

pub fn enarx_run<'a>(path: &str, input: impl Into<Option<&'a [u8]>>) -> Output {
    let url = Url::from_file_path(
        Path::new(CRATE)
            .join(OUT_DIR)
            .join(TEST_BINS_OUT)
            .join(path),
    )
    .unwrap();

    let mut child = Command::new(&KEEP_BIN);
    let child = child
        .current_dir(CRATE)
        .arg("run")
        .arg(url.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = child
        .spawn()
        .unwrap_or_else(|e| panic!("failed to run `{}`: {:#?}", path, e));

    let input_thread = if let Some(input) = input.into() {
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
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
        .time_limit(time::Duration::from_secs(TIMEOUT_SECS))
        .terminate_for_timeout()
        .wait()
        .unwrap_or_else(|e| panic!("failed to run `{}`: {:#?}", path, e))
        .unwrap_or_else(|| panic!("`{}` process timed out", path));

    if let Some(input_thread) = input_thread {
        if let Err(_) = input_thread.join() {
            let _unused = stderr().write_all(&output.stderr);
            panic!("failed to provide input for process `{}`", path)
        }
    }

    assert!(
        output.status.code().is_some(),
        "`{}` process terminated by signal {:?}",
        path,
        output.status.signal()
    );

    output
}

fn compile(wasm: &str) {
    let out_dir = Path::new(CRATE).join(OUT_DIR).join(TEST_BINS_OUT);
    let wasm = out_dir.join(wasm);

    create(&out_dir);

    let src_path = &Path::new(CRATE).join("tests/crates/enarx_wasm_tests/wat");

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
    path: &str,
    status: i32,
    input: impl Into<Option<&'a [u8]>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) -> Output {
    let output = enarx_run(path, input);
    check_output(&output, status, expected_stdout, expected_stderr);
    output
}

fn run_wat_test<'a>(
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
#[serial]
fn return_1() {
    // This module does, in fact, return 1. But function return values
    // are separate from setting the process exit status code, so
    // we still expect a return code of '0' here.
    run_wat_test("return_1.wasm", 0, None, None, None);
}

#[test]
#[serial]
fn wasi_snapshot1() {
    // This module uses WASI to return the number of commandline args.
    // Since we don't currently do anything with the function return value,
    // we don't get any output here, and we expect '0', as above.
    run_wat_test("wasi_snapshot1.wasm", 0, None, None, None);
}

#[test]
#[serial]
fn hello_wasi_snapshot1() {
    // This module just prints "Hello, world!" to stdout. Hooray!
    run_wat_test(
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
    // This module has no exported functions, so we get an error.
    run_wat_test("no_export.wasm", 1, None, None, None);
}

#[test]
#[serial]
fn echo() {
    let mut input: Vec<u8> = Vec::with_capacity(2 * 1024 * 1024);

    for i in 0..input.capacity() {
        input.push(i as _);
    }
    let input = input.as_slice();

    let bin = env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_echo");
    run_wasm_test(bin, 0, input, input, None);
}

#[test]
#[serial]
fn memspike() {
    let bin = env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_memspike");
    run_wasm_test(bin, 0, None, None, None);
}

#[test]
#[serial]
fn memory_stress_test() {
    let bin = env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_memory_stress_test");
    run_wasm_test(bin, 0, None, None, None);
}

#[test]
#[serial]
fn zerooneone() {
    let input = b"Good morning, that's a nice tnetennba.\n0118 999 881 999 119 725 3\n";

    let bin = env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_zerooneone");
    let output = b"Tbbq zbeavat, gung'f n avpr gargraaon.\n0118 999 881 999 119 725 3\n";
    run_wasm_test(bin, 0, input.as_slice(), output.as_slice(), None);
}

#[test]
#[serial]
fn check_tcp() {
    const MSG: &str = "one\ntwo\nthree\n";
    const CFG: &str = r#"
        [[files]]
        kind = "stdin"

        [[files]]
        kind = "stdout"

        [[files]]
        kind = "stderr"

        [[files]]
        kind = "listen"
        prot = "tcp"
        port = @@LPORT@@
        name = "LISTEN"

        [[files]]
        kind = "connect"
        prot = "tcp"
        host = "127.0.0.1"
        port = @@CPORT@@
        name = "CONNECT"
    "#;

    // Create listening sockets (allocate a port).
    let listen = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let connect = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let lport = listen.local_addr().unwrap().port();
    let cport = connect.local_addr().unwrap().port();
    drop(connect);

    let pkg = tempdir().expect("failed to create temporary directory");

    fs::copy(
        env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_check_tcp"),
        pkg.path().join("main.wasm"),
    )
    .expect("failed to copy WASM module");

    fs::write(
        pkg.path().join("Enarx.toml"),
        CFG.replace("@@LPORT@@", &cport.to_string())
            .replace("@@CPORT@@", &lport.to_string()),
    )
    .expect("failed to write config");

    // Spawn the IO thread.
    let background = thread::spawn(move || {
        let mut output = listen.accept().unwrap().0;
        output.write_all(MSG.as_bytes()).unwrap();
        drop(output);

        let mut input = TcpStream::connect(("127.0.0.1", cport)).unwrap();
        let mut buffer = String::new();
        input.read_to_string(&mut buffer).unwrap();
        drop(input);

        buffer
    });

    run_wasm_test(pkg.path().to_str().unwrap(), 0, None, None, None);

    let output = background.join().unwrap();
    assert_eq!(MSG, &output);
}
