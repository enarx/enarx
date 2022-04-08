// SPDX-License-Identifier: Apache-2.0

#![feature(core_ffi_c)]

use rust_exec_tests::musl_fsbase_fix;
use std::io::{self, stdin, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

musl_fsbase_fix!();

fn main() -> io::Result<()> {
    let mut dir_name = String::new();

    stdin().read_line(&mut dir_name)?;

    let dir_name = PathBuf::from(dir_name);

    let listener = UnixListener::bind(dir_name.join("enarx_unix_echo_to_bin"))?;
    let (mut socket, _) = listener.accept()?;

    let mut buffer = Vec::new();
    socket.read_to_end(&mut buffer)?;

    let mut socket = UnixStream::connect(dir_name.join("enarx_unix_echo_from_bin")).unwrap();
    socket.write_all(&buffer)?;
    Ok(())
}
