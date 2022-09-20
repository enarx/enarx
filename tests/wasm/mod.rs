// SPDX-License-Identifier: Apache-2.0

use super::{check_output, enarx, CRATE, EXEC, OUT_DIR, TEST_BINS_OUT};

use std::borrow::BorrowMut;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{ensure, Context};
use async_std::io::WriteExt;
use async_std::net::{TcpListener, TcpStream};
use drawbridge_client::Url;
use futures::io::BufReader;
use futures::task::SpawnExt;
use futures::{AsyncBufReadExt, AsyncRead, AsyncWrite, Future};
use futures_rustls::TlsConnector;
use futures_test::test;
use process_control::Output;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::version::TLS13;
use rustls::Certificate;
use tempfile::{tempdir, NamedTempFile};

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
    use std::ffi::OsStr;

    let tmpdir = tempdir().expect("failed to create temporary package directory");
    let signature_file_path = tmpdir.path().join("sig.json");

    let out = enarx(
        |cmd| {
            cmd.args(vec![
                OsStr::new("sign"),
                OsStr::new("--sgx-key"),
                OsStr::new("tests/data/sgx-test.key"),
                OsStr::new("--sev-id-key"),
                OsStr::new("tests/data/sev-id.key"),
                OsStr::new("--sev-id-key-signature"),
                OsStr::new("tests/data/sev-id-key-signature.blob"),
                OsStr::new("--out"),
                signature_file_path.as_os_str(),
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

    let ret = enarx(
        |cmd| {
            let cmd = cmd.arg("run").arg(wasm).args(vec![
                OsStr::new("--signatures"),
                signature_file_path.as_os_str(),
            ]);
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

pub fn enarx_deploy<'a>(url: &Url, input: impl Into<Option<&'a [u8]>>) -> Output {
    enarx(|cmd| cmd.arg("deploy").arg(url.as_str()), input)
}

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
async fn return_1() {
    // This module does, in fact, return 1. But function return values
    // are separate from setting the process exit status code, so
    // we still expect a return code of '0' here.
    let wasm = compile("return_1.wasm");
    check_output(&enarx_run(&wasm, None, None), 0, None, None);
}

#[test]
async fn wasi_snapshot1() {
    // This module uses WASI to return the number of commandline args.
    // Since we don't currently do anything with the function return value,
    // we don't get any output here, and we expect '0', as above.
    let wasm = compile("wasi_snapshot1.wasm");
    check_output(&enarx_run(&wasm, None, None), 0, None, None);
}

#[test]
async fn hello_wasi_snapshot1() {
    // This module just prints "Hello, world!" to stdout. Hooray!
    let wasm = compile("hello_wasi_snapshot1.wasm");
    const OUTPUT: &[u8] = br#"Hello, world!
"#;
    check_output(&enarx_run(&wasm, None, None), 0, OUTPUT, None);
}

#[test]
async fn no_export() {
    // This module has no exported functions, so we get an error.
    let wasm = compile("no_export.wasm");
    check_output(&enarx_run(&wasm, None, None), 1, None, None);
}

#[test]
async fn echo() {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_echo"));

    let mut input: Vec<_> = Vec::with_capacity(2 * 1024 * 1024);
    for i in 0..input.capacity() {
        input.push(i as _);
    }
    let input = input.as_slice();
    check_output(&enarx_run(&wasm, None, input), 0, input, None);
}

#[test]
async fn memspike() {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_memspike"));
    check_output(&enarx_run(&wasm, None, None), 0, None, None);
}

#[test]
async fn memory_stress_test() {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_memory_stress_test"));
    check_output(&enarx_run(&wasm, None, None), 0, None, None);
}

#[test]
async fn zerooneone() -> anyhow::Result<()> {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_zerooneone"));
    const INPUT: &[u8] = br#"Good morning, that's a nice tnetennba.
0118 999 881 999 119 725 3
"#;
    const OUTPUT: &[u8] = br#"Tbbq zbeavat, gung'f n avpr gargraaon.
0118 999 881 999 119 725 3
"#;

    check_output(&enarx_run(&wasm, None, INPUT), 0, OUTPUT, None);

    let url = Url::from_file_path(&wasm).expect("failed to construct a URL from path");
    check_output(&enarx_deploy(&url, INPUT), 0, OUTPUT, None);

    const CONF: &str = r#"[[files]]
kind = "stdin"

[[files]]
kind = "stdout"

[[files]]
kind = "stderr""#;

    // TODO: Extract the `enarx deploy` test into a separate test case or use `enarx deploy`
    // in all test cases.
    let pkg = tempdir().context("failed to create temporary package directory")?;
    let pkg_wasm = pkg.path().join("main.wasm");
    let pkg_conf = pkg.path().join("Enarx.toml");

    fs::copy(&wasm, &pkg_wasm).context("failed to copy WASM module")?;
    fs::write(&pkg_conf, CONF).context("failed to write config")?;

    check_output(&enarx_run(&wasm, Some(&pkg_conf), INPUT), 0, OUTPUT, None);

    let url = Url::from_file_path(&pkg).expect("failed to construct a URL from package path");
    check_output(&enarx_deploy(&url, None), 0, None, None);

    // TODO: Test execution from a remote HTTP(S) URL
    // https://github.com/enarx/enarx/issues/1855
    Ok(())
}

async fn assert_copy_line(
    stream: &mut BufReader<impl AsyncRead + AsyncWrite + Unpin>,
) -> anyhow::Result<()> {
    stream
        .write_all(b"test")
        .await
        .context("failed to write line")?;
    let mut line = String::new();
    stream
        .read_line(&mut line)
        .await
        .context("failed to read line")?;
    ensure!(line == "test\n");
    ensure!(stream.buffer().is_empty());
    Ok(())
}

async fn assert_stream<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: impl BorrowMut<T>,
) -> anyhow::Result<()> {
    let mut stream = BufReader::new(stream.borrow_mut());
    assert_copy_line(&mut stream)
        .await
        .context("failed to copy first line")?;
    assert_copy_line(&mut stream)
        .await
        .context("failed to copy second line")?;
    assert_copy_line(&mut stream)
        .await
        .context("failed to copy third line")?;
    Ok(())
}

#[test]
async fn connect_tcp() -> anyhow::Result<()> {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_connect"));

    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("failed to start TCP listener")?;
    let port = listener
        .local_addr()
        .context("failed to query listener local address")?
        .port();

    let mut conf = NamedTempFile::new().context("failed to create config file")?;
    write!(
        conf,
        r#"[[files]]
kind = "stdin"

[[files]]
kind = "stdout"

[[files]]
kind = "stderr"

[[files]]
kind = "connect"
prot = "tcp"
host = "{}"
port = {port}
name = "stream""#,
        Ipv4Addr::LOCALHOST,
    )
    .context("failed to write config file")?;

    let server = EXEC
        .spawn_with_handle(async move {
            let (stream, _) = listener
                .accept()
                .await
                .context("failed to accept connection")?;
            assert_stream(stream)
                .await
                .context("failed to assert stream")
        })
        .expect("failed to spawn server");
    check_output(&enarx_run(&wasm, Some(&conf.path()), None), 0, None, None);
    server.await
}

// TODO: Reenable once there's functionality to configure trust anchors in Enarx.toml
// https://github.com/enarx/enarx/issues/2170 (which requires VFS)
//#[test]
//async fn connect_tls() -> anyhow::Result<()> {
//    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_connect"));
//
//    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
//        .await
//        .context("failed to start TCP listener")?;
//    let port = listener
//        .local_addr()
//        .context("failed to query listener local address")?
//        .port();
//
//    let mut conf = NamedTempFile::new().context("failed to create config file")?;
//    write!(
//        conf,
//        r#"[[files]]
//kind = "stdin"
//
//[[files]]
//kind = "stdout"
//
//[[files]]
//kind = "stderr"
//
//[[files]]
//kind = "connect"
//prot = "tls"
//host = "localhost"
//port = {port}
//name = "stream"
//ca = {{ custom = [ "test" ] }}
//
//[roots]
//test = """\
//{}\
//""""#,
//        include_str!("../../tests/data/tls/ca.crt")
//    )
//    .context("failed to write config file")?;
//
//    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
//        include_bytes!("../../tests/data/tls/server.crt").as_slice(),
//    ))
//    .context("failed to read server TLS certificates")?
//    .into_iter()
//    .map(Certificate)
//    .collect();
//
//    let key = match rustls_pemfile::read_one(&mut std::io::BufReader::new(
//        include_bytes!("../../tests/data/tls/server.key").as_slice(),
//    ))
//    .context("failed to read server TLS certificate key")?
//    .context("server TLS certificate key missing")?
//    {
//        RSAKey(buf) | PKCS8Key(buf) | ECKey(buf) => PrivateKey(buf),
//        item => bail!("unsupported key type `{:?}`", item),
//    };
//
//    let tls: TlsAcceptor = Arc::new(
//        rustls::ServerConfig::builder()
//            .with_safe_default_cipher_suites()
//            .with_safe_default_kx_groups()
//            .with_protocol_versions(&[&TLS13])
//            .context("failed to select TLS protocol versions")?
//            .with_no_client_auth() // TODO: Validate client cert
//            .with_single_cert(certs, key)
//            .context("invalid server TLS certificate key")?,
//    )
//    .into();
//
//    let server = EXEC
//        .spawn_with_handle(async move {
//            let (stream, _) = listener
//                .accept()
//                .await
//                .context("failed to accept connection")?;
//            let tls = tls
//                .accept(stream)
//                .await
//                .context("failed to create TLS connection")?;
//            assert_stream(tls).await.context("failed to assert stream")
//        })
//        .expect("failed to spawn server");
//    check_output(&enarx_run(&wasm, Some(&conf.path()), None), 0, None, None);
//    server.await
//}

async fn assert_connect<F, T>(connect: impl Fn() -> F) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = anyhow::Result<T>>,
{
    let stream = connect()
        .await
        .context("failed to establish first connection")?;
    assert_stream(stream)
        .await
        .context("failed to assert first stream")?;

    let stream = connect()
        .await
        .context("failed to establish second connection")?;
    assert_stream(stream)
        .await
        .context("failed to assert second stream")?;

    let stream = connect()
        .await
        .context("failed to establish third connection")?;
    assert_stream(stream)
        .await
        .context("failed to assert third stream")?;

    Ok(())
}

#[test]
#[cfg_attr(windows, ignore = "listener tests hang on Windows")]
async fn listen_tcp() -> anyhow::Result<()> {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_listen"));

    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("failed to start TCP listener")?;
    let port = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("failed to start TCP listener")?
        .local_addr()
        .context("failed to query listener local address")?
        .port();

    let mut conf = NamedTempFile::new().context("failed to create config file")?;
    write!(
        conf,
        r#"[[files]]
kind = "stdin"

[[files]]
kind = "stdout"

[[files]]
kind = "stderr"

[[files]]
kind = "listen"
prot = "tcp"
port = {port}
name = "ingest"

[[files]]
kind = "connect"
prot = "tcp"
host = "{}"
port = {}
name = "ping""#,
        Ipv4Addr::LOCALHOST,
        listener.local_addr().unwrap().port()
    )
    .context("failed to write config file")?;

    let client = EXEC
        .spawn_with_handle(async move {
            _ = listener
                .accept()
                .await
                .context("failed to accept connection")?;

            assert_connect(|| async {
                TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .context("failed to connect to TCP socket")
            })
            .await
            .context("failed to assert TCP connection")
        })
        .expect("failed to spawn client");
    check_output(&enarx_run(&wasm, Some(&conf.path()), None), 0, None, None);
    client.await
}

struct NoopCertVerifier;

impl ServerCertVerifier for NoopCertVerifier {
    fn verify_server_cert(
        &self,
        _: &Certificate,
        _: &[Certificate],
        _: &rustls::ServerName,
        _: &mut dyn Iterator<Item = &[u8]>,
        _: &[u8],
        _: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[test]
#[cfg_attr(windows, ignore = "listener tests hang on Windows")]
async fn listen_tls() -> anyhow::Result<()> {
    let wasm = wasm_path(env!("CARGO_BIN_FILE_ENARX_WASM_TESTS_listen"));

    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("failed to start TCP listener")?;
    let port = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("failed to start TCP listener")?
        .local_addr()
        .context("failed to query listener local address")?
        .port();

    let mut conf = NamedTempFile::new().context("failed to create config file")?;
    write!(
        conf,
        r#"[[files]]
kind = "stdin"

[[files]]
kind = "stdout"

[[files]]
kind = "stderr"

[[files]]
kind = "listen"
prot = "tls"
port = {port}
name = "ingest"

[[files]]
kind = "connect"
prot = "tcp"
host = "{}"
port = {}
name = "ping""#,
        Ipv4Addr::LOCALHOST,
        listener.local_addr().unwrap().port()
    )
    .context("failed to write config file")?;

    let tls: TlsConnector = Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&TLS13])
            .context("failed to select TLS protocol versions")?
            .with_custom_certificate_verifier(Arc::new(NoopCertVerifier))
            .with_no_client_auth(),
    )
    .into();

    let client = EXEC
        .spawn_with_handle(async move {
            _ = listener
                .accept()
                .await
                .expect("failed to accept connection");

            assert_connect(|| async {
                let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .context("failed to connect to TLS socket")?;
                tls.connect("localhost".try_into().unwrap(), stream)
                    .await
                    .context("failed to create TLS connection")
            })
            .await
            .context("failed to assert TLS connection")
        })
        .expect("failed to spawn client");
    check_output(&enarx_run(&wasm, Some(&conf.path()), None), 0, None, None);
    client.await
}
