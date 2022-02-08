// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "wasmldr")]
#![cfg(not(feature = "gdb"))]

use process_control::{ChildExt, Control, Output};
use serial_test::serial;
use std::fs::File;
use tempfile::tempdir;

use std::io::Write;
use std::net;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time;

pub mod common;
use common::{check_output, run_crate, CRATE, KEEP_BIN, OUT_DIR, TEST_BINS_OUT, TIMEOUT_SECS};

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
        .controlled_with_output()
        .time_limit(time::Duration::from_secs(TIMEOUT_SECS))
        .terminate_for_timeout()
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

#[test]
#[serial]
fn echo() {
    let mut input: Vec<u8> = Vec::with_capacity(2 * 1024 * 1024);

    for i in 0..input.capacity() {
        input.push(i as _);
    }

    let expected_input = input.clone();

    run_crate(
        "tests/wasm/rust-tests",
        "echo",
        None,
        0,
        input,
        expected_input.as_slice(),
        None,
    );
}

#[test]
#[serial]
fn memspike() {
    run_crate(
        "tests/wasm/rust-tests",
        "memspike",
        None,
        0,
        None,
        None,
        None,
    );
}

#[test]
#[serial]
fn memory_stress_test() {
    run_crate(
        "tests/wasm/rust-tests",
        "memory_stress_test",
        None,
        0,
        None,
        None,
        None,
    );
}

#[test]
#[serial]
fn zerooneone() {
    let input = Vec::from("Good morning, that's a nice tnetennba.\n0118 999 881 999 119 725 3\n");

    run_crate(
        "tests/wasm/rust-tests",
        "zerooneone",
        None,
        0,
        input,
        &b"Tbbq zbeavat, gung'f n avpr gargraaon.\n0118 999 881 999 119 725 3\n"[..],
        None,
    );
}

#[test]
#[serial]
fn check_listen_fd() {
    use std::sync::mpsc::channel;

    enum ThreadFinished {
        Client,
        Server,
    }

    let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let tmpdir = tempdir().unwrap();
    let configfile_path = tmpdir.path().join("config.toml");
    let mut configfile = File::create(&configfile_path).unwrap();
    let configfile_path = configfile_path.to_str().unwrap();

    let (tx, rx) = channel::<ThreadFinished>();

    let client_handle = thread::spawn({
        let tx = tx.clone();
        move || {
            let result = std::panic::catch_unwind(|| {
                use std::io::Read;
                // Retry connecting until the server started hopefully
                for i in (0..600).rev() {
                    thread::sleep(time::Duration::from_secs(1));
                    let res = net::TcpStream::connect(("127.0.0.1", port));
                    if res.is_err() {
                        if i > 0 {
                            continue;
                        } else {
                            panic!("Failed to connect to 127.0.0.1:{port}");
                        }
                    }

                    let mut stream = res.unwrap();
                    let mut buf = String::new();
                    stream.read_to_string(&mut buf).unwrap();
                    assert_eq!(buf, "Hello World!");
                    break;
                }
            });

            tx.send(ThreadFinished::Client).unwrap();
            if result.is_err() {
                panic!("client thread panicked");
            }
        }
    });

    write!(
        configfile,
        r#"
[[files]]
type = "stdio"
name = "stdin"

[[files]]
type = "stdio"
name = "stdout"

[[files]]
type = "stdio"
name = "stderr"

[[files]]
type = "tcp_listen"
addr = "127.0.0.1"
port = {}
name = "TEST_TCP_LISTEN"
    "#,
        port
    )
    .unwrap();
    drop(configfile);

    let server_handle = thread::spawn({
        let configfile_path = configfile_path.to_owned();
        move || {
            let result = std::panic::catch_unwind(|| {
                run_crate(
                    "tests/wasm/rust-tests",
                    "check_listen_fd",
                    &["--wasmcfgfile", &configfile_path][..],
                    0,
                    None,
                    None,
                    None,
                );
            });

            tx.send(ThreadFinished::Server).unwrap();
            if result.is_err() {
                panic!("server thread panicked");
            }
        }
    });

    match rx.recv().unwrap() {
        ThreadFinished::Client => {
            client_handle.join().unwrap();
            server_handle.join().unwrap();
        }
        ThreadFinished::Server => {
            server_handle.join().unwrap();
            client_handle.join().unwrap();
        }
    }
}
