// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::sync::Arc;

use cap_std::net::{TcpListener, TcpStream};
use io_lifetimes::{AsFilelike, AsSocketlike};
use rustix::fd::AsFd;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};
use system_interface::fs::GetSetFdFlags;
use system_interface::io::{IsReadWrite, ReadReady};
use wasi_common::file::{FdFlags, FileType};
use wasi_common::{Context, Error, ErrorExt, WasiFile};
use wasmtime_wasi::net::from_sysif_fdflags;

pub struct Stream {
    tcp: TcpStream,
    tls: Connection,
}

impl From<Stream> for Box<dyn WasiFile> {
    fn from(value: Stream) -> Self {
        Box::new(value)
    }
}

impl Stream {
    pub fn connect(mut tcp: TcpStream, name: &str, cfg: Arc<ClientConfig>) -> Result<Self, Error> {
        // Set up connection.
        let tls = ClientConnection::new(cfg, name.try_into()?)?;
        let mut tls = Connection::Client(tls);

        // Finish the connection.
        tls.complete_io(&mut tcp)?;

        Ok(Self { tcp, tls })
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
        if self.tls.wants_read() {
            self.tls.read_tls(&mut self.tcp)?;
            self.tls.process_new_packets()?;
        }

        let n = match self.tls.reader().read_vectored(bufs) {
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e.into()),
            Ok(n) => n,
        };

        Ok(n as u64)
    }

    async fn write_vectored<'a>(&mut self, bufs: &[IoSlice<'a>]) -> Result<u64, Error> {
        let n = self.tls.writer().write_vectored(bufs)?;

        while self.tls.wants_write() {
            self.tls.write_tls(&mut self.tcp)?;
        }

        Ok(n as u64)
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
    listener: TcpListener,
    config: Arc<ServerConfig>,
}

impl Listener {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> Self {
        Self { listener, config }
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
        let (mut tcp, ..) = self.listener.accept()?;

        // Create a new TLS connection.
        let mut tls = Connection::Server(
            ServerConnection::new(self.config.clone())
                .map_err(|e| Error::io().context(e))
                .context("could not create new TLS connection")?,
        );
        // Perform handshake.
        tls.complete_io(&mut tcp)
            .map_err(|e| Error::io().context(e))
            .context("could not perform TLS handshake")?;

        let mut stream = Stream { tcp, tls };
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

    async fn num_ready_bytes(&self) -> Result<u64, Error> {
        Ok(1)
    }
}
