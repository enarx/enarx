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
    eprintln!("[guest] reading line");
    loop {
        match stream.read_line(&mut line) {
            Ok(_) => break,
            Err(e) if nonblocking && e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => bail!(anyhow!(e).context("failed to read line from host")),
        }
    }
    eprintln!("[guest] writing line `{line}` back to the host");
    loop {
        match write!(stream.get_mut(), "{line}") {
            Ok(_) => break,
            Err(e) if nonblocking && e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => bail!(anyhow!(e).context("failed to write line to host")),
        }
    }
    Ok(())
}

pub fn assert_stream(mut stream: impl BorrowMut<TcpStream>) -> anyhow::Result<()> {
    let mut stream = BufReader::new(stream.borrow_mut());

    eprintln!("[guest] copying first line on default stream");
    assert_copy_line(&mut stream, false).context("failed to copy first line")?;
    ensure!(stream.buffer().is_empty());

    stream
        .get_ref()
        .set_nonblocking(false)
        .context("failed to unset NONBLOCK")?;

    eprintln!("[guest] copying second line on blocking stream");
    assert_copy_line(&mut stream, false).context("failed to copy second line")?;
    ensure!(stream.buffer().is_empty());

    stream
        .get_ref()
        .set_nonblocking(true)
        .context("failed to set NONBLOCK")?;

    eprintln!("[guest] copying third line on nonblocking stream");
    assert_copy_line(&mut stream, true).context("failed to copy third line")?;
    ensure!(stream.buffer().is_empty());

    Ok(())
}
