// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(target_os = "wasi")]
use std::os::wasi::io::FromRawFd;

#[cfg(any(target_os = "wasi", unix))]
fn main() -> anyhow::Result<()> {
    use enarx_wasm_tests::assert_stream;

    use std::env;
    use std::net::TcpStream;

    use anyhow::{ensure, Context};

    let fd_count: usize = env::var("FD_COUNT")
        .context("failed to lookup `FD_COUNT`")?
        .parse()
        .context("failed to parse `FD_COUNT`")?;
    ensure!(
        fd_count == 4, // STDIN, STDOUT, STDERR and the socket connected to the endpoint
        "unexpected amount of file descriptors received"
    );
    ensure!(
        env::var("FD_NAMES").context("failed to lookup `FD_NAMES`")?
            == "stdin:stdout:stderr:stream"
    );

    assert_stream(unsafe { TcpStream::from_raw_fd(3) })
}

#[cfg(not(any(target_os = "wasi", unix)))]
fn main() {
    panic!("unsupported on this target")
}
