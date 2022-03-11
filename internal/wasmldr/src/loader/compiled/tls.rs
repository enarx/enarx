// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::io;
use std::io::{Read, Write};
use std::sync::{Arc, RwLock};

use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};
use wasi_common::file::{FdFlags, FileType};
use wasi_common::{Context, Error, ErrorExt, WasiFile};

pub struct Stream(RwLock<(std::net::TcpStream, Connection)>);

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

        Ok(Self(RwLock::new((tcp, tls))))
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
        Ok(FdFlags::APPEND | FdFlags::NONBLOCK)
    }

    async fn read_vectored<'a>(&mut self, bufs: &mut [io::IoSliceMut<'a>]) -> Result<u64, Error> {
        let (tcp, tls) = &mut *self.0.write().unwrap();

        if tls.wants_read() {
            tls.read_tls(tcp)
                .map_err(|e| Error::io().context(e))
                .context("could not read TLS ciphertext from TCP stream")?;

            tls.process_new_packets()
                .map_err(|e| Error::io().context(e))
                .context("could not process new TLS packets")?;
        }

        let n = tls
            .reader()
            .read_vectored(bufs)
            .map_err(|e| match e.kind() {
                io::ErrorKind::UnexpectedEof => Error::io().context("unexpected EOF"),
                _ => Error::io(),
            })
            .context("could not read decrypted TLS ciphertext")?;

        Ok(n as u64)
    }

    async fn write_vectored<'a>(&mut self, bufs: &[io::IoSlice<'a>]) -> Result<u64, Error> {
        let (tcp, tls) = &mut *self.0.write().unwrap();

        let n = tls
            .writer()
            .write_vectored(bufs)
            .map_err(|e| Error::io().context(e))
            .context("could not write plaintext to TLS buffer ciphertext")?;

        while tls.wants_write() {
            tls.write_tls(tcp)
                .map_err(|e| Error::io().context(e))
                .context("could not write TLS ciphertext on TCP stream")?;
        }

        Ok(n as u64)
    }

    async fn readable(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn writable(&self) -> Result<(), Error> {
        Ok(())
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

        Ok(Box::new(Stream(RwLock::new((tcp, tls)))))
    }

    async fn get_filetype(&mut self) -> Result<FileType, Error> {
        Ok(FileType::SocketStream)
    }

    async fn get_fdflags(&mut self) -> Result<FdFlags, Error> {
        Ok(FdFlags::NONBLOCK)
    }
}
