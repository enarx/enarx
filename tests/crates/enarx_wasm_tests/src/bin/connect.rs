// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "wasi", feature(wasi_ext))]

#[cfg(any(target_os = "wasi", unix))]
fn main() -> anyhow::Result<()> {
    use enarx_wasm_tests::assert_stream;

    use std::env::args;
    use std::fs::File;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
    use std::num::NonZeroU16;
    #[cfg(unix)]
    use std::os::unix::io::OwnedFd;
    #[cfg(target_os = "wasi")]
    use std::os::wasi::io::OwnedFd;

    use anyhow::{bail, ensure, Context};

    let mut args = args();
    ensure!(args.next().as_deref() == Some("main.wasm"));
    let port: NonZeroU16 = match (args.next(), args.next()) {
        (Some(port), None) => port
            .parse()
            .context("failed to parse port from arguments")?,
        _ => bail!("takes exactly one argument (port)"),
    };

    eprintln!("[guest] connecting to `{}:{port}`", Ipv4Addr::LOCALHOST);
    let stream = File::options()
        .read(true)
        .write(true)
        .open(format!("/net/con/{}:{port}", Ipv4Addr::LOCALHOST))
        .map(OwnedFd::from)
        .map(TcpStream::from)
        .with_context(|| format!("failed to connect to `{}:{port}`", Ipv4Addr::LOCALHOST))?;
    assert_stream(stream).context("failed to assert IPv4 connectivity")?;

    eprintln!("[guest] connecting to `[{}]:{port}`", Ipv6Addr::LOCALHOST);
    let stream = File::options()
        .read(true)
        .write(true)
        .open(format!("/net/con/[{}]:{port}", Ipv6Addr::LOCALHOST))
        .map(OwnedFd::from)
        .map(TcpStream::from)
        .with_context(|| format!("failed to connect to `[{}]:{port}`", Ipv6Addr::LOCALHOST))?;
    assert_stream(stream).context("failed to assert IPv6 connectivity")?;

    Ok(())
}

#[cfg(not(any(target_os = "wasi", unix)))]
fn main() {
    panic!("unsupported on this target")
}
