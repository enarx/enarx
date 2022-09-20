// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "wasi", feature(wasi_ext))]

use enarx_wasm_tests::assert_stream;

use std::net::TcpListener;
use std::{env, io};

#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(target_os = "wasi")]
use std::os::wasi::io::FromRawFd;

use anyhow::{ensure, anyhow, Context, bail};

fn main() -> anyhow::Result<()> {
    let fd_count: usize = env::var("FD_COUNT")
        .context("failed to lookup `FD_COUNT`")?
        .parse()
        .context("failed to parse `FD_COUNT`")?;
    ensure!(
        fd_count == 5, // STDIN, STDOUT, STDERR, the listening socket and a ping stream
        "unexpected amount of file descriptors received"
    );
    ensure!(
        env::var("FD_NAMES").context("failed to lookup `FD_NAMES`")?
            == "stdin:stdout:stderr:ingest:ping"
    );

    let listener = unsafe { TcpListener::from_raw_fd(3) };
    let (stream, _) = listener
        .accept()
        .context("failed to accept first connection")?;
    assert_stream(stream).context("failed to assert default stream")?;

    listener
        .set_nonblocking(false)
        .context("failed to unset NONBLOCK")?;
    let (stream, _) = listener
        .accept()
        .context("failed to accept second connection")?;
    assert_stream(stream).context("failed to assert blocking stream")?;

    listener
        .set_nonblocking(true)
        .context("failed to set NONBLOCK")?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                assert_stream(stream).context("failed to assert non-blocking stream")?;
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => bail!(anyhow!(e).context("failed to accept third connection")),
        }
    }
    Ok(())
}
