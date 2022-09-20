// SPDX-License-Identifier: Apache-2.0

use std::borrow::BorrowMut;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

use anyhow::{anyhow, bail, ensure, Context};

pub fn assert_copy_line(
    stream: &mut BufReader<impl Read + Write>,
    nonblocking: bool,
) -> anyhow::Result<()> {
    let mut line = String::new();
    loop {
        match stream.read_line(&mut line) {
            Ok(_) => break,
            Err(e) if nonblocking && e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => bail!(anyhow!(e).context("failed to read line")),
        }
    }
    loop {
        match write!(stream.get_mut(), "{line}") {
            Ok(_) => break,
            Err(e) if nonblocking && e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => bail!(anyhow!(e).context("failed to write line")),
        }
    }
    Ok(())
}

pub fn assert_stream(mut stream: impl BorrowMut<TcpStream>) -> anyhow::Result<()> {
    let mut stream = BufReader::new(stream.borrow_mut());

    assert_copy_line(&mut stream, false).context("failed to copy first line")?;
    ensure!(stream.buffer().is_empty());

    stream
        .get_ref()
        .set_nonblocking(false)
        .context("failed to unset NONBLOCK")?;
    assert_copy_line(&mut stream, false).context("failed to copy second line")?;
    ensure!(stream.buffer().is_empty());

    stream
        .get_ref()
        .set_nonblocking(true)
        .context("failed to set NONBLOCK")?;
    assert_copy_line(&mut stream, true).context("failed to copy third line")?;
    ensure!(stream.buffer().is_empty());
    Ok(())
}
