// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "wasi", feature(wasi_ext))]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

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

    assert_eq!(fd_names, "stdin:stdout:stderr:LISTEN:CONNECT");
    assert_eq!(fd_count, 5);

    // Set up the environment sockets.
    let connect = unsafe { TcpStream::from_raw_fd(4) };
    let listen = unsafe { TcpListener::from_raw_fd(3) };

    // Accept the incoming connection.
    let mut socket = listen.accept().unwrap().0;

    // Output all incoming lines to the output.
    let reader = BufReader::new(connect);
    for line in reader.lines() {
        let line = line.unwrap();
        socket.write_all(line.as_bytes()).unwrap();
        socket.write_all(b"\n").unwrap();
    }

    Ok(())
}
