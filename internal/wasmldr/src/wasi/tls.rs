// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::io;
use std::io::{Read, Write};
use std::ops::DerefMut;
use std::os::unix::prelude::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex};

use io_lifetimes::{AsFd, BorrowedFd};
use rustls::{Connection, ServerConfig, ServerConnection};
use wasi_common::file::{Advice, FdFlags, FileType, Filestat};
use wasi_common::{Context, Error, ErrorExt, WasiFile};
use wasmtime_wasi::net::{TcpListener, TcpStream};

pub struct Stream {
    raw_stream: Mutex<cap_std::net::TcpStream>,
    raw_stream_file: Box<dyn WasiFile>,
    tls_connection: Mutex<Connection>,
}

#[wiggle::async_trait]
impl WasiFile for Stream {
    fn as_any(&self) -> &dyn Any {
        self.raw_stream_file.as_any()
    }

    async fn sock_accept(&mut self, _fdflags: FdFlags) -> Result<Box<dyn WasiFile>, Error> {
        Err(Error::badf())
    }

    async fn datasync(&self) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn sync(&self) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn get_filetype(&self) -> Result<FileType, Error> {
        self.raw_stream_file.get_filetype().await
    }

    async fn get_fdflags(&self) -> Result<FdFlags, Error> {
        self.raw_stream_file.get_fdflags().await
    }

    async fn set_fdflags(&mut self, fdflags: FdFlags) -> Result<(), Error> {
        self.raw_stream_file.set_fdflags(fdflags).await
    }

    async fn get_filestat(&self) -> Result<Filestat, Error> {
        Err(Error::badf())
    }

    async fn set_filestat_size(&self, _size: u64) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn advise(&self, _offset: u64, _len: u64, _advice: Advice) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn allocate(&self, _offset: u64, _len: u64) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn set_times(
        &self,
        _atime: Option<wasi_common::SystemTimeSpec>,
        _mtime: Option<wasi_common::SystemTimeSpec>,
    ) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn read_vectored<'a>(&self, bufs: &mut [io::IoSliceMut<'a>]) -> Result<u64, Error> {
        let mut tls_connection = self
            .tls_connection
            .lock()
            .map_err(|e| Error::trap(format!("could not get TLS connection from mutex: {}", e)))?;

        let mut raw_stream = self
            .raw_stream
            .lock()
            .map_err(|e| Error::trap(format!("could not get TCP stream from mutex: {}", e)))?;

        if tls_connection.wants_read() {
            tls_connection
                .read_tls(raw_stream.deref_mut())
                .map_err(|e| Error::io().context(e))
                .context("could not read TLS ciphertext from TCP stream")?;
            tls_connection
                .process_new_packets()
                .map_err(|e| Error::io().context(e))
                .context("could not process new TLS packets")?;
        }
        tls_connection
            .reader()
            .read_vectored(bufs)
            .map_err(|e| match e.kind() {
                io::ErrorKind::UnexpectedEof => Error::io().context("unexpected EOF"),
                _ => Error::io(),
            })
            .context("could not read decrypted TLS ciphertext")?
            .try_into()
            .map_err(|e| Error::range().context(e))
    }

    async fn read_vectored_at<'a>(
        &self,
        _bufs: &mut [io::IoSliceMut<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn write_vectored<'a>(&self, bufs: &[io::IoSlice<'a>]) -> Result<u64, Error> {
        let mut tls_connection = self
            .tls_connection
            .lock()
            .map_err(|e| Error::trap(format!("could not get TLS connection from mutex: {}", e)))?;

        let mut raw_stream = self
            .raw_stream
            .lock()
            .map_err(|e| Error::trap(format!("could not get TCP stream from mutex: {}", e)))?;

        let n = tls_connection
            .writer()
            .write_vectored(bufs)
            .map_err(|e| Error::io().context(e))
            .context("could not write plaintext to TLS buffer ciphertext")?
            .try_into()
            .map_err(|e| Error::range().context(e))?;
        tls_connection
            .write_tls(raw_stream.deref_mut())
            .map_err(|e| Error::io().context(e))
            .context("could not write TLS ciphertext on TCP stream")?;
        Ok(n)
    }

    async fn write_vectored_at<'a>(
        &self,
        _bufs: &[io::IoSlice<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn seek(&self, _pos: std::io::SeekFrom) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn peek(&self, _buf: &mut [u8]) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn num_ready_bytes(&self) -> Result<u64, Error> {
        self.raw_stream_file.num_ready_bytes().await
    }

    fn isatty(&self) -> bool {
        self.raw_stream_file.isatty()
    }

    async fn readable(&self) -> Result<(), Error> {
        self.raw_stream_file.readable().await
    }

    async fn writable(&self) -> Result<(), Error> {
        self.raw_stream_file.writable().await
    }
}

pub struct Listener {
    raw_listener: wasmtime_wasi::net::TcpListener,
    tls_config: Arc<ServerConfig>,
}

impl Listener {
    pub fn new(listener: std::net::TcpListener, tls_config: Arc<ServerConfig>) -> Self {
        Self {
            raw_listener: TcpListener::from_cap_std(wasmtime_wasi::sync::TcpListener::from_std(
                listener,
            )),
            tls_config,
        }
    }
}

#[wiggle::async_trait]
impl WasiFile for Listener {
    fn as_any(&self) -> &dyn Any {
        self.raw_listener.as_any()
    }

    async fn sock_accept(&mut self, fdflags: FdFlags) -> Result<Box<dyn WasiFile>, Error> {
        let raw_stream_file = self
            .raw_listener
            .sock_accept(fdflags)
            .await
            .context("could not accept TCP connection")?;

        let raw_stream_fd = raw_stream_file
            .as_any()
            .downcast_ref::<TcpStream>()
            .ok_or(Error::trap(
                "could not downcast underlying stream to TCP stream",
            ))?
            .as_fd()
            .as_raw_fd();

        // Safety: FD is owned by us, this is only required because wasmtime 0.35.0 does not
        // provide a way to retrieve underlying cap_std::net::TcpStream from TcpStream wrapper.
        let mut raw_stream = unsafe { cap_std::net::TcpStream::from_raw_fd(raw_stream_fd) };

        let mut tls_connection = ServerConnection::new(self.tls_config.clone())
            .map_err(|e| Error::io().context(e))
            .context("could not create new TLS connection")?;
        tls_connection
            .complete_io(&mut raw_stream)
            .map_err(|e| Error::io().context(e))
            .context("could not perform TLS handshake")?;

        Ok(Box::new(Stream {
            raw_stream: Mutex::new(raw_stream),
            raw_stream_file,
            tls_connection: Mutex::new(tls_connection.into()),
        }))
    }

    async fn datasync(&self) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn sync(&self) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn get_filetype(&self) -> Result<FileType, Error> {
        self.raw_listener.get_filetype().await
    }

    async fn get_fdflags(&self) -> Result<FdFlags, Error> {
        self.raw_listener.get_fdflags().await
    }

    async fn set_fdflags(&mut self, fdflags: FdFlags) -> Result<(), Error> {
        self.raw_listener.set_fdflags(fdflags).await
    }

    async fn get_filestat(&self) -> Result<Filestat, Error> {
        Err(Error::badf())
    }

    async fn set_filestat_size(&self, _size: u64) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn advise(&self, _offset: u64, _len: u64, _advice: Advice) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn allocate(&self, _offset: u64, _len: u64) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn set_times(
        &self,
        _atime: Option<wasi_common::SystemTimeSpec>,
        _mtime: Option<wasi_common::SystemTimeSpec>,
    ) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn read_vectored<'a>(&self, _bufs: &mut [io::IoSliceMut<'a>]) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn read_vectored_at<'a>(
        &self,
        _bufs: &mut [io::IoSliceMut<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn write_vectored<'a>(&self, _bufs: &[io::IoSlice<'a>]) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn write_vectored_at<'a>(
        &self,
        _bufs: &[io::IoSlice<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn seek(&self, _pos: std::io::SeekFrom) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn peek(&self, _buf: &mut [u8]) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn num_ready_bytes(&self) -> Result<u64, Error> {
        self.raw_listener.num_ready_bytes().await
    }

    fn isatty(&self) -> bool {
        self.raw_listener.isatty()
    }

    async fn readable(&self) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn writable(&self) -> Result<(), Error> {
        Err(Error::badf())
    }
}

impl AsFd for Listener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.raw_listener.as_fd()
    }
}
