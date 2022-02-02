// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "wasi", feature(wasi_ext))]

use std::io::Write;
use std::net::TcpListener;

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

#[cfg(target_os = "wasi")]
use std::os::wasi::io::FromRawFd;

fn main() -> std::io::Result<()> {
    let listen_fds: i32 = std::env::var("LISTEN_FDS")
        .expect("No LISTEN_FDS")
        .parse()
        .expect("Failed to parse LISTEN_FDS to i32");

    let listen_fdnames = std::env::var("LISTEN_FDNAMES").expect("No LISTEN_FDNAMES");

    dbg!(listen_fds);
    dbg!(listen_fdnames);

    assert_eq!(listen_fds, 1);

    let listener = unsafe { TcpListener::from_raw_fd(3) };

    listener.set_nonblocking(false).unwrap();

    let (mut stream, _addr) = listener.accept()?;

    stream.set_nonblocking(false).unwrap();

    stream.write_all(b"Hello World!")?;

    Ok(())
}
