// SPDX-License-Identifier: Apache-2.0
//! A WasiFile for transparent TLS

use std::any::Any;
use std::io;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::sync::Arc;

use cap_std::net::{TcpListener as CapListener, TcpStream as CapStream};
use io_lifetimes::{AsFd, AsFilelike};
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};
use system_interface::fs::GetSetFdFlags;
use system_interface::io::IsReadWrite;
use wasi_common::file::{FdFlags, FileType};
use wasi_common::{Context, Error, ErrorExt, ErrorKind, WasiFile};
use wasmtime_wasi::net::from_sysif_fdflags;

fn errmap(error: std::io::Error) -> Error {
    use std::io::ErrorKind::*;

    match error.kind() {
        WouldBlock => ErrorKind::WouldBlk.into(),
        InvalidInput => ErrorKind::Inval.into(),
        Unsupported => ErrorKind::Notsup.into(),
        InvalidData => ErrorKind::Inval.into(),
        _ => Error::from(ErrorKind::Io).context(error),
    }
}

trait IOAsync {
    fn complete_io_async<T>(&mut self, io: &mut T) -> Result<(usize, usize), io::Error>
    where
        Self: Sized,
        T: io::Read + io::Write;
}

impl IOAsync for Connection {
    /// This function uses `io` to complete any outstanding IO for this connection.
    ///
    /// Based upon [`complete_io`], but with added `flush()` and `WouldBlock` error handling for async connections.
    ///
    /// [`complete_io`]: https://github.com/rustls/rustls/blob/c42c53e13dfc54495cbb62577f6bb58eddf5ff8a/rustls/src/conn.rs#L462-L507
    fn complete_io_async<T>(&mut self, io: &mut T) -> Result<(usize, usize), io::Error>
    where
        Self: Sized,
        T: io::Read + io::Write,
    {
        let until_handshaked = self.is_handshaking();
        let mut eof = false;
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            while self.wants_write() {
                let res = self.write_tls(io);
                if matches!(&res, Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
                    break;
                }
                wrlen += res?;
            }

            if !until_handshaked && wrlen > 0 {
                let _ignored = io.flush();
                return Ok((rdlen, wrlen));
            }

            if !eof && self.wants_read() {
                match self.read_tls(io) {
                    Ok(0) => eof = true,
                    Ok(n) => rdlen += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok((rdlen, wrlen)),
                    Err(e) => return Err(e),
                }
            }

            match self.process_new_packets() {
                Ok(_) => {}
                Err(e) => {
                    // In case we have an alert to send describing this error,
                    // try a last-gasp write -- but don't predate the primary
                    // error.
                    let _ignored = self.write_tls(io);
                    let _ignored = io.flush();

                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            };

            match (eof, until_handshaked, self.is_handshaking()) {
                (_, true, false) => return Ok((rdlen, wrlen)),
                (_, false, _) => return Ok((rdlen, wrlen)),
                (true, true, true) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                (..) => {}
            }
        }
    }
}

pub struct Stream {
    tcp: CapStream,
    tls: Connection,
}

impl From<Stream> for Box<dyn WasiFile> {
    fn from(value: Stream) -> Self {
        Box::new(value)
    }
}

impl Stream {
    pub fn connect(mut tcp: CapStream, name: &str, cfg: Arc<ClientConfig>) -> Result<Self, Error> {
        // Set up connection.
        let tls = ClientConnection::new(cfg, name.try_into()?)?;
        let mut tls = Connection::Client(tls);

        // Finish the connection.
        tls.complete_io(&mut tcp)?;

        Ok(Self { tcp, tls })
    }

    fn complete_io(&mut self) -> Result<(), Error> {
        self.tls.complete_io_async(&mut self.tcp).map_err(errmap)?;
        Ok(())
    }
}

#[wiggle::async_trait]
impl WasiFile for Stream {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn get_filetype(&mut self) -> Result<FileType, Error> {
        Ok(FileType::SocketStream)
    }

    async fn get_fdflags(&mut self) -> Result<FdFlags, Error> {
        let fdflags = self.tcp.as_filelike().get_fd_flags()?;
        Ok(from_sysif_fdflags(fdflags))
    }

    async fn set_fdflags(&mut self, fdflags: FdFlags) -> Result<(), Error> {
        if fdflags == FdFlags::NONBLOCK {
            self.tcp.set_nonblocking(true)?;
        } else if fdflags.is_empty() {
            self.tcp.set_nonblocking(false)?;
        } else {
            return Err(Error::invalid_argument().context("cannot set anything else than NONBLOCK"));
        }
        Ok(())
    }

    async fn read_vectored<'a>(&mut self, bufs: &mut [IoSliceMut<'a>]) -> Result<u64, Error> {
        self.complete_io()?;

        self.tls
            .reader()
            .read_vectored(bufs)
            .map_err(errmap)?
            .try_into()
            .map_err(|e| Error::range().context(e))
    }

    async fn write_vectored<'a>(&mut self, bufs: &[IoSlice<'a>]) -> Result<u64, Error> {
        self.complete_io()?;

        let n = self
            .tls
            .writer()
            .write_vectored(bufs)
            .map_err(errmap)?
            .try_into()
            .map_err(|e| Error::range().context(e))?;

        self.complete_io()?;
        Ok(n)
    }

    async fn readable(&self) -> Result<(), Error> {
        let (readable, _writeable) = self.tcp.is_read_write()?;
        if readable {
            Ok(())
        } else {
            Err(Error::io())
        }
    }
    async fn writable(&self) -> Result<(), Error> {
        let (_readable, writeable) = self.tcp.is_read_write()?;
        if writeable {
            Ok(())
        } else {
            Err(Error::io())
        }
    }

    fn pollable(&self) -> Option<rustix::fd::BorrowedFd<'_>> {
        Some(self.tcp.as_fd())
    }
}

pub struct Listener {
    listener: CapListener,
    cfg: Arc<ServerConfig>,
}

impl Listener {
    pub fn new(listener: CapListener, cfg: Arc<ServerConfig>) -> Self {
        Self { listener, cfg }
    }
}

impl From<Listener> for Box<dyn WasiFile> {
    fn from(value: Listener) -> Self {
        Box::new(value)
    }
}

#[wiggle::async_trait]
impl WasiFile for Listener {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn pollable(&self) -> Option<rustix::fd::BorrowedFd<'_>> {
        Some(self.listener.as_fd())
    }

    async fn sock_accept(&mut self, fdflags: FdFlags) -> Result<Box<dyn WasiFile>, Error> {
        // Accept the connection.
        let (tcp, ..) = self.listener.accept()?;

        // Create a new TLS connection.
        let tls = Connection::Server(
            ServerConnection::new(self.cfg.clone())
                .map_err(|e| Error::io().context(e))
                .context("could not create new TLS connection")?,
        );

        tcp.set_nonblocking(false)?;
        let mut stream = Stream { tcp, tls };
        stream.complete_io()?;

        stream.set_fdflags(fdflags).await?;
        Ok(Box::new(stream))
    }

    async fn get_filetype(&mut self) -> Result<FileType, Error> {
        Ok(FileType::SocketStream)
    }

    async fn get_fdflags(&mut self) -> Result<FdFlags, Error> {
        let fdflags = self.listener.as_filelike().get_fd_flags()?;
        Ok(from_sysif_fdflags(fdflags))
    }

    async fn set_fdflags(&mut self, fdflags: FdFlags) -> Result<(), Error> {
        if fdflags == FdFlags::NONBLOCK {
            self.listener.set_nonblocking(true)?;
        } else if fdflags.is_empty() {
            self.listener.set_nonblocking(false)?;
        } else {
            return Err(Error::invalid_argument().context("cannot set anything else than NONBLOCK"));
        }
        Ok(())
    }

    async fn read_vectored<'a>(
        &mut self,
        _bufs: &mut [std::io::IoSliceMut<'a>],
    ) -> Result<u64, Error> {
        Ok(0)
    }

    async fn read_vectored_at<'a>(
        &mut self,
        _bufs: &mut [std::io::IoSliceMut<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Ok(0)
    }

    async fn write_vectored<'a>(&mut self, bufs: &[std::io::IoSlice<'a>]) -> Result<u64, Error> {
        Ok(bufs.iter().map(|b| b.len() as u64).sum())
    }

    async fn write_vectored_at<'a>(
        &mut self,
        bufs: &[std::io::IoSlice<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Ok(bufs.iter().map(|b| b.len() as u64).sum())
    }

    async fn peek(&mut self, _buf: &mut [u8]) -> Result<u64, Error> {
        Ok(0)
    }

    async fn readable(&self) -> Result<(), Error> {
        Ok(())
    }
}
