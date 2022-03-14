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
    dbg!(fd_names);

    assert_eq!(fd_count, 4);

    let listener = unsafe { TcpListener::from_raw_fd(3) };

    listener.set_nonblocking(false).unwrap();

    let (mut stream, _addr) = listener.accept()?;

    stream.set_nonblocking(false).unwrap();

    stream.write_all(b"Hello World!")?;

    Ok(())
}
