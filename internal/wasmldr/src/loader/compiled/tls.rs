// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::sync::Arc;

use rustix::fd::AsFd;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};
use wasi_common::file::{FdFlags, FileType};
use wasi_common::{Context, Error, ErrorExt, WasiFile};

pub struct Stream {
    tcp: std::net::TcpStream,
    tls: Connection,
}

impl From<Stream> for Box<dyn WasiFile> {
    fn from(value: Stream) -> Self {
        Box::new(value)
    }
}

impl Stream {
    pub fn connect(
        mut tcp: std::net::TcpStream,
        name: &str,
        cfg: Arc<ClientConfig>,
    ) -> Result<Self, Error> {
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
        Ok(FdFlags::APPEND)
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
        Ok(())
    }

    async fn writable(&self) -> Result<(), Error> {
        Ok(())
    }

    fn pollable(&self) -> Option<rustix::fd::BorrowedFd<'_>> {
        Some(self.tcp.as_fd())
    }
}

pub struct Listener {
    listener: std::net::TcpListener,
    config: Arc<ServerConfig>,
}

impl Listener {
    pub fn new(listener: std::net::TcpListener, config: Arc<ServerConfig>) -> Self {
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

    async fn sock_accept(&mut self, fdflags: FdFlags) -> Result<Box<dyn WasiFile>, Error> {
        // Accept the connection.
        let (mut tcp, ..) = self.listener.accept()?;
        tcp.set_nonblocking(fdflags.contains(FdFlags::NONBLOCK))?;

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

        Ok(Box::new(Stream { tcp, tls }))
    }

    async fn get_filetype(&mut self) -> Result<FileType, Error> {
        Ok(FileType::SocketStream)
    }

    async fn get_fdflags(&mut self) -> Result<FdFlags, Error> {
        Ok(FdFlags::empty())
    }

    fn pollable(&self) -> Option<rustix::fd::BorrowedFd<'_>> {
        Some(self.listener.as_fd())
    }
}
