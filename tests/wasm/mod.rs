// SPDX-License-Identifier: Apache-2.0

use super::{check_output, CRATE, KEEP_BIN, OUT_DIR, TEST_BINS_OUT, TIMEOUT_SECS};

use std::io::{stderr, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time;
use std::{fs, thread};

use process_control::{ChildExt, Control, Output};
use serial_test::serial;
use tempfile::tempdir;

fn enarx<'a>(
    cmd: impl FnOnce(&mut Command) -> &mut Command,
    input: impl Into<Option<&'a [u8]>>,
) -> Output {
    let mut child = cmd(Command::new(&KEEP_BIN)
        .current_dir(CRATE)
        .env(
            "ENARX_TEST_SGX_KEY_FILE",
            CRATE.to_string() + "/tests/data/sgx-test.key",
        )
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

    #[cfg(unix)]
    assert!(
        output.status.code().is_some(),
        "process terminated by signal {:?}",
        output.status.signal()
    );

    output
}

#[cfg(not(enarx_with_shim))]
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

#[cfg(enarx_with_shim)]
pub fn enarx_run<'a>(
    wasm: &Path,
    conf: Option<&Path>,
    input: impl Into<Option<&'a [u8]>>,
) -> Output {
    let tmpdir = tempdir().expect("failed to create temporary package directory");

    let out = enarx(
        |cmd| {
            cmd.args(vec![
                "sign",
                "--sgx-key",
                "tests/data/sgx-test.key",
                "--sev-key",
                "tests/data/sev-id.key",
                "--sev-author-key",
                "tests/data/sev-author.key",
            ])
        },
        None,
    );

    if !out.status.success() {
        eprintln!(
            "failed to sign package: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return out;
    }

    let signature_file_path = tmpdir.path().join("sig.json");
    fs::write(&signature_file_path, &out.stdout).expect("failed to write signature file");

    let ret = enarx(
        |cmd| {
            let cmd = cmd
                .arg("run")
                .arg(wasm)
                .args(vec!["--signatures", signature_file_path.to_str().unwrap()]);
            if let Some(conf) = conf {
                cmd.args(vec!["--wasmcfgfile", conf.to_str().unwrap()])
            } else {
                cmd
            }
        },
        input,
    );

    tmpdir.close().unwrap();

    ret
}

//pub fn enarx_deploy<'a>(url: &Url, input: impl Into<Option<&'a [u8]>>) -> Output {
//    enarx(|cmd| cmd.arg("deploy").arg(url.as_str()), input)
//}

fn wasm_out() -> PathBuf {
    Path::new(CRATE).join(OUT_DIR).join(TEST_BINS_OUT)
}

fn wasm_path(wasm: &str) -> PathBuf {
    wasm_out().join(wasm)
}

fn compile(wasm: &str) -> PathBuf {
    let wasm = wasm_path(wasm);

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
            return wasm;
        }
    }

    let out_dir = wasm_out();
    match fs::create_dir(&out_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            eprintln!("Can't create {:#?} : {:#?}", out_dir, e);
            std::process::exit(1);
        }
        Ok(_) => {}
    }
    let bin = wat::parse_file(&wat).unwrap_or_else(|_| panic!("failed to compile {:?}", &wat));
    fs::write(&wasm, &bin).unwrap_or_else(|_| panic!("failed to write {:?}", &wasm));
    wasm
}

#[test]
#[serial]
fn return_1() {
    // This module does, in fact, return 1. But function return values
    // are separate from setting the process exit status code, so
    // we still expect a return code of '0' here.
    let wasm = compile("return_1.wasm");
    check_output(&enarx_run(&wasm, None, None), 0, None, None);
}

#[test]
#[serial]
fn wasi_snapshot1() {
    // This module uses WASI to return the number of commandline args.
    // Since we don't currently do anything with the function return value,
    // we don't get any output here, and we expect '0', as above.
    let wasm = compile("wasi_snapshot1.wasm");
    check_output(&enarx_run(&wasm, None, None), 0, None, None);
}

#[test]
#[serial]
fn hello_wasi_snapshot1() {
    // This module just prints "Hello, world!" to stdout. Hooray!
    let wasm = compile("hello_wasi_snapshot1.wasm");
    const OUTPUT: &[u8] = br#"Hello, world!
"#;
    check_output(&enarx_run(&wasm, None, None), 0, OUTPUT, None);
}

#[test]
#[serial]
fn no_export() {
    // This module has no exported functions, so we get an error.
    let wasm = compile("no_export.wasm");
    check_output(&enarx_run(&wasm, None, None), 1, None, None);
}

#[test]
#[serial]
fn echo() {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_echo"));

    let mut input: Vec<_> = Vec::with_capacity(2 * 1024 * 1024);
    for i in 0..input.capacity() {
        input.push(i as _);
    }
    let input = input.as_slice();
    check_output(&enarx_run(&wasm, None, input), 0, input, None);
}

#[test]
#[serial]
fn memspike() {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_memspike"));
    check_output(&enarx_run(&wasm, None, None), 0, None, None);
}

#[test]
#[serial]
fn memory_stress_test() {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_memory_stress_test"));
    check_output(&enarx_run(&wasm, None, None), 0, None, None);
}

#[test]
#[serial]
fn zerooneone() {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_zerooneone"));
    const INPUT: &[u8] = br#"Good morning, that's a nice tnetennba.
0118 999 881 999 119 725 3
"#;
    const OUTPUT: &[u8] = br#"Tbbq zbeavat, gung'f n avpr gargraaon.
0118 999 881 999 119 725 3
"#;

    check_output(&enarx_run(&wasm, None, INPUT), 0, OUTPUT, None);

    // TODO: reinstate these tests with the new `enarx deploy` slug
    //let url = Url::from_file_path(&wasm).expect("failed to construct a URL from path");
    //check_output(&enarx_deploy(&url, INPUT), 0, OUTPUT, None);

    // TODO: Test execution from a remote HTTP(S) URL
    // https://github.com/enarx/enarx/issues/1855
}

#[test]
#[serial]
fn check_tcp() {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_check_tcp"));

    // Create listening sockets (allocate a port).
    let listen = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let lport = listen.local_addr().unwrap().port();
    let cport = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let conf = format!(
        r#"[[files]]
kind = "stdin"

[[files]]
kind = "stdout"

[[files]]
kind = "stderr"

[[files]]
kind = "listen"
prot = "tcp"
port = {cport}
name = "LISTEN"
addr = "0.0.0.0"

[[files]]
kind = "connect"
prot = "tcp"
host = "127.0.0.1"
port = {lport}
name = "CONNECT""#
    );

    let pkg = tempdir().expect("failed to create temporary package directory");
    let pkg_wasm = pkg.path().join("main.wasm");
    let pkg_conf = pkg.path().join("Enarx.toml");

    fs::copy(wasm, &pkg_wasm).expect("failed to copy WASM module");
    fs::write(&pkg_conf, &conf).expect("failed to write config");

    // Spawn the IO thread.
    thread::spawn(move || loop {
        let mut output = listen.accept().unwrap().0;
        output.write_all(b"test").unwrap();
        drop(output);

        let mut input = TcpStream::connect((Ipv4Addr::LOCALHOST, cport)).unwrap();
        let mut buffer = String::new();
        input.read_to_string(&mut buffer).unwrap();
        drop(input);

        assert_eq!("test\n", buffer)
    });

    check_output(&enarx_run(&pkg_wasm, Some(&pkg_conf), None), 0, None, None);

    // TODO: reinstate these tests with the new `enarx deploy` slug
    //let url = Url::from_file_path(&pkg).expect("failed to construct a URL from package path");
    //check_output(&enarx_deploy(&url, None), 0, None, None);

    // TODO: Test execution from a remote HTTP(S) URL
    // https://github.com/enarx/enarx/issues/1855
}
