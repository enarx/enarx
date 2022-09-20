// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "wasi", feature(wasi_ext))]

#[cfg(any(target_os = "wasi", unix))]
fn main() -> anyhow::Result<()> {
    use enarx_wasm_tests::assert_stream;

    use std::env::args;
    use std::fs::File;
    use std::io::{self, Read};
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
    use std::num::NonZeroU16;
    #[cfg(unix)]
    use std::os::unix::io::OwnedFd;
    #[cfg(target_os = "wasi")]
    use std::os::wasi::io::OwnedFd;
    use std::thread;
    use std::time::Duration;

    use anyhow::{anyhow, bail, ensure, Context};

    fn assert_listener(port: NonZeroU16) -> anyhow::Result<()> {
        eprintln!("[guest] listening on `{port}`");
        let listener = File::options()
            .read(true)
            .write(true)
            .open(format!("/net/lis/{port}"))
            .map(OwnedFd::from)
            .map(TcpListener::from)
            .with_context(|| format!("failed to listen on port `{port}`"))?;

        eprintln!("[guest] accepting on default listener");
        let (stream, _) = listener
            .accept()
            .context("failed to accept connection on default listener stream")?;

        eprintln!("[guest] asserting connectivity over default listener stream");
        assert_stream(stream).context("failed to assert default listener stream")?;

        listener
            .set_nonblocking(false)
            .context("failed to unset NONBLOCK")?;

        eprintln!("[guest] accepting on blocking listener");
        let (stream, _) = listener
            .accept()
            .context("failed to accept connection on blocking listener stream")?;

        eprintln!("[guest] asserting connectivity over blocking listener stream");
        assert_stream(stream).context("failed to assert blocking listener stream")?;

        listener
            .set_nonblocking(true)
            .context("failed to set NONBLOCK")?;
        loop {
            eprintln!("[guest] accepting on non-blocking listener");
            match listener.accept() {
                Ok((stream, _)) => {
                    eprintln!("[guest] asserting connectivity over non-blocking listener stream");
                    assert_stream(stream)
                        .context("failed to assert non-blocking listener stream")?;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100))
                }
                Err(e) => {
                    bail!(anyhow!(e)
                        .context("failed to accept connection on non-blocking listener stream"))
                }
            }
        }
        Ok(())
    }

    let mut args = args();
    ensure!(args.next().as_deref() == Some("main.wasm"));
    let cport: u16 = match (args.next(), args.next()) {
        (Some(cport), None) => cport
            .parse()
            .context("failed to parse port from arguments")?,
        _ => bail!("takes exactly one argument (port)"),
    };

    eprintln!(
        "[guest] connecting to `{}:{cport}` to read listening port",
        Ipv4Addr::LOCALHOST
    );
    let mut lport = String::new();
    _ = File::options()
        .read(true)
        .write(true)
        .open(format!("/net/con/{}:{cport}", Ipv4Addr::LOCALHOST))
        .map(OwnedFd::from)
        .map(TcpStream::from)
        .context("failed to open stream")?
        .read_to_string(&mut lport)
        .context("failed to read listening port")?;
    let lport: NonZeroU16 = lport
        .trim()
        .parse()
        .context("failed to parse port from stream")?;

    eprintln!("[guest] asserting IPv4 connectivity");
    assert_listener(lport).context("failed to assert IPv4 connectivity")?;

    eprintln!(
        "[guest] connecting to `[{}]:{cport}` to signal listener closure",
        Ipv6Addr::LOCALHOST
    );
    _ = File::options()
        .read(true)
        .write(true)
        .open(format!("/net/con/[{}]:{cport}", Ipv6Addr::LOCALHOST));

    eprintln!("[guest] asserting IPv6 connectivity");
    assert_listener(lport).context("failed to assert IPv6 connectivity")?;
    Ok(())
}

#[cfg(not(any(target_os = "wasi", unix)))]
fn main() {
    panic!("unsupported on this target")
}
