// SPDX-License-Identifier: Apache-2.0

use super::{check_output, CRATE, KEEP_BIN, OUT_DIR, TEST_BINS_OUT, TIMEOUT_SECS};

use std::io::{stderr, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time;
use std::{fs, thread};

use process_control::{ChildExt, Control, Output};
use serial_test::serial;
use tempfile::tempdir;
use url::Url;

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

fn enarx<'a>(
    cmd: impl FnOnce(&mut Command) -> &mut Command,
    input: impl Into<Option<&'a [u8]>>,
) -> Output {
    let mut child = cmd(Command::new(&KEEP_BIN)
        .current_dir(CRATE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()))
    .spawn()
    .unwrap_or_else(|e| panic!("failed to execute command: {:#?}", e));

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
        .unwrap_or_else(|e| panic!("failed to run command: {:#?}", e))
        .unwrap_or_else(|| panic!("process timed out"));

    if let Some(input_thread) = input_thread {
        if let Err(_) = input_thread.join() {
            let _unused = stderr().write_all(&output.stderr);
            panic!("failed to provide input for process")
        }
    }

    assert!(
        output.status.code().is_some(),
        "process terminated by signal {:?}",
        output.status.signal()
    );

    output
}

pub fn enarx_run<'a>(
    wasm: &Path,
    conf: Option<&Path>,
    input: impl Into<Option<&'a [u8]>>,
) -> Output {
    enarx(
        |cmd| {
            let cmd = cmd.arg("run").arg(wasm);
            if let Some(conf) = conf {
                cmd.args(vec!["--wasmcfgfile", conf.to_str().unwrap()])
            } else {
                cmd
            }
        },
        input,
    )
}

pub fn enarx_deploy<'a>(url: &Url, input: impl Into<Option<&'a [u8]>>) -> Output {
    enarx(|cmd| cmd.arg("deploy").arg(url.as_str()), input)
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

const DEFAULT_CONFIG: &str = r#"[[files]]
kind = "stdin"

[[files]]
kind = "stdout"

[[files]]
kind = "stderr""#;

fn run_wasm_test<'a>(
    wasm: &str,
    conf: Option<&'a str>,
    status: i32,
    input: impl Into<Option<&'a [u8]>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) {
    let input = input.into();
    let expected_stdout = expected_stdout.into();
    let expected_stderr = expected_stderr.into();

    let wasm = Path::new(CRATE)
        .join(OUT_DIR)
        .join(TEST_BINS_OUT)
        .join(wasm);

    if conf.is_none() {
        check_output(
            &enarx_run(&wasm, None, input),
            status,
            expected_stdout,
            expected_stderr,
        );

        check_output(
            &enarx_deploy(
                &Url::from_file_path(&wasm).expect("failed to construct a URL from path"),
                input,
            ),
            status,
            expected_stdout,
            expected_stderr,
        );

        // TODO: Test execution from a remote HTTP(S) URL
    }

    let pkg = tempdir().expect("failed to create temporary package directory");
    let pkg_wasm = pkg.path().join("main.wasm");
    let pkg_conf = pkg.path().join("Enarx.toml");

    fs::copy(wasm, &pkg_wasm).expect("failed to copy WASM module");
    fs::write(&pkg_conf, &conf.unwrap_or(DEFAULT_CONFIG)).expect("failed to write config");

    check_output(
        &enarx_run(pkg_wasm.as_path(), Some(pkg_conf.as_path()), input),
        status,
        expected_stdout,
        expected_stderr,
    );

    check_output(
        &enarx_deploy(
            &Url::from_file_path(pkg.path()).expect("failed to construct a URL from package path"),
            input,
        ),
        status,
        expected_stdout,
        expected_stderr,
    )

    // TODO: Test execution from a remote HTTP(S) URL
}

fn run_wat_test<'a>(
    wasm: &str,
    conf: Option<&'a str>,
    status: i32,
    input: impl Into<Option<&'a [u8]>>,
    expected_stdout: impl Into<Option<&'a [u8]>>,
    expected_stderr: impl Into<Option<&'a [u8]>>,
) {
    compile(wasm);
    run_wasm_test(wasm, conf, status, input, expected_stdout, expected_stderr);
}

#[test]
#[serial]
fn return_1() {
    // This module does, in fact, return 1. But function return values
    // are separate from setting the process exit status code, so
    // we still expect a return code of '0' here.
    run_wat_test("return_1.wasm", None, 0, None, None, None);
}

#[test]
#[serial]
fn wasi_snapshot1() {
    // This module uses WASI to return the number of commandline args.
    // Since we don't currently do anything with the function return value,
    // we don't get any output here, and we expect '0', as above.
    run_wat_test("wasi_snapshot1.wasm", None, 0, None, None, None);
}

#[test]
#[serial]
fn hello_wasi_snapshot1() {
    // This module just prints "Hello, world!" to stdout. Hooray!
    run_wat_test(
        "hello_wasi_snapshot1.wasm",
        None,
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
    run_wat_test("no_export.wasm", None, 1, None, None, None);
}

#[test]
#[serial]
fn echo() {
    let mut input: Vec<_> = Vec::with_capacity(2 * 1024 * 1024);
    for i in 0..input.capacity() {
        input.push(i as _);
    }
    let input = input.as_slice();

    const WASM: &str = env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_echo");
    run_wasm_test(WASM, None, 0, input, input, None);
}

#[test]
#[serial]
fn memspike() {
    const WASM: &str = env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_memspike");
    run_wasm_test(WASM, None, 0, None, None, None);
}

#[test]
#[serial]
fn memory_stress_test() {
    const WASM: &str = env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_memory_stress_test");
    run_wasm_test(WASM, None, 0, None, None, None);
}

#[test]
#[serial]
fn zerooneone() {
    const WASM: &str = env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_zerooneone");
    const INPUT: &str = r#"Good morning, that's a nice tnetennba.
0118 999 881 999 119 725 3
"#;
    const OUTPUT: &str = r#"Tbbq zbeavat, gung'f n avpr gargraaon.
0118 999 881 999 119 725 3
"#;
    run_wasm_test(WASM, None, 0, INPUT.as_bytes(), OUTPUT.as_bytes(), None);
}

#[test]
#[serial]
fn check_tcp() {
    const MSG: &str = r#"one
two
three
"#;
    const CFG: &str = r#"[[files]]
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
name = "CONNECT""#;

    // Create listening sockets (allocate a port).
    let listen = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let connect = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let lport = listen.local_addr().unwrap().port();
    let cport = connect.local_addr().unwrap().port();
    drop(connect);

    // Spawn the IO thread.
    thread::spawn(move || loop {
        let mut output = listen.accept().unwrap().0;
        output.write_all(MSG.as_bytes()).unwrap();
        drop(output);

        let mut input = TcpStream::connect((Ipv4Addr::LOCALHOST, cport)).unwrap();
        let mut buffer = String::new();
        input.read_to_string(&mut buffer).unwrap();
        drop(input);

        assert_eq!(MSG, buffer)
    });

    const WASM: &str = env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_check_tcp");
    let cfg = CFG
        .replace("@@LPORT@@", &cport.to_string())
        .replace("@@CPORT@@", &lport.to_string());
    run_wasm_test(WASM, Some(cfg.as_str()), 0, None, None, None);
}
