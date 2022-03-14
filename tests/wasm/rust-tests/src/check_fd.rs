// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "wasi", feature(wasi_ext))]

use std::io::Write;
use std::net::TcpListener;

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

#[cfg(target_os = "wasi")]
use std::os::wasi::io::FromRawFd;

fn main() -> std::io::Result<()> {
    let fd_count: i32 = std::env::var("FD_COUNT")
        .expect("No FD_COUNT")
        .parse()
        .expect("Failed to parse FD_COUNT to i32");

    let fd_names = std::env::var("FD_NAMES").expect("No FD_NAMES");

    assert_eq!(
        fd_names,
        "stdin:stdout:stderr:TEST_TCP_LISTEN:TEST_TLS_LISTEN"
    );
    assert_eq!(fd_count, 5);

    let tcp_listener = unsafe { TcpListener::from_raw_fd(3) };
    tcp_listener.set_nonblocking(false).unwrap();

    let (mut tcp_stream, _addr) = tcp_listener.accept()?;
    tcp_stream.set_nonblocking(false).unwrap();
    tcp_stream.write_all(b"Hello World!")?;

    let tls_listener = unsafe { TcpListener::from_raw_fd(4) };
    tls_listener.set_nonblocking(false).unwrap();

    let (mut tls_stream, _addr) = tls_listener.accept()?;
    tls_stream.set_nonblocking(false).unwrap();
    tls_stream.write_all(b"Hello World!")?;

    Ok(())
}
