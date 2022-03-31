// SPDX-License-Identifier: Apache-2.0
//! A WasiFile for transparent TLS

use std::any::Any;
use std::io;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::forget;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, RwLock};

use cap_std::net::{TcpListener as CapListener, TcpStream as CapStream};
use rustix::fd::{AsRawFd, FromRawFd};
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};
use wasi_common::file::{Advice, FdFlags, FileType, Filestat};
use wasi_common::{Context, Error, ErrorExt, ErrorKind, WasiFile};
use wasmtime_wasi::net::{TcpListener as AnyListener, TcpStream as AnyStream};

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

/// A type which leaks whatever it wraps
///
/// The use of this type is due to a hack below. The `WasiCtx` does internal
/// downcasts in order to get the file descriptor for polling. We have fixed
/// this upstream, but the fix is not yet released. Therefore, we need to
/// create a "borrowed" instance of that type for polling purposes. This
/// "borrowed" instance MUST NOT call `close()` on its file descriptor.
struct Forgotten<T>(Option<T>);

impl<T> Deref for Forgotten<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl<T> DerefMut for Forgotten<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}

impl<T> From<T> for Forgotten<T> {
    fn from(value: T) -> Self {
        Self(Some(value))
    }
}

impl<T> Drop for Forgotten<T> {
    fn drop(&mut self) {
        forget(self.0.take());
    }
}

pub struct Stream {
    lck: RwLock<(Forgotten<CapStream>, Connection)>,
    any: AnyStream,
}

impl From<Stream> for Box<dyn WasiFile> {
    fn from(value: Stream) -> Self {
        Box::new(value)
    }
}

impl Stream {
    fn new(tcp: CapStream, tls: Connection) -> Self {
        // Safety: We create a "borrowed" (i.e. `Forgotten`) copy of `CapStream`.
        // The `AnyStream` is the real owner of the file descriptor.
        // This is a workaround until wasmtime 0.36.0 is released.
        let cap = unsafe { CapStream::from_raw_fd(tcp.as_raw_fd()) }.into();
        let any = AnyStream::from_cap_std(tcp);
        Self {
            lck: RwLock::new((cap, tls)),
            any,
        }
    }

    pub fn connect(mut tcp: CapStream, name: &str, cfg: Arc<ClientConfig>) -> Result<Self, Error> {
        // Set up connection.
        let tls = ClientConnection::new(cfg, name.try_into()?)?;
        let mut tls = Connection::Client(tls);

        // Finish the connection.
        tls.complete_io(&mut tcp)?;

        Ok(Self::new(tcp, tls))
    }

    fn complete_io(&self) -> Result<(), Error> {
        let (cap, tls) = &mut *self.lck.write().unwrap();
        tls.complete_io_async(cap.deref_mut()).map_err(errmap)?;
        Ok(())
    }
}

#[wiggle::async_trait]
impl WasiFile for Stream {
    fn as_any(&self) -> &dyn Any {
        self.any.as_any()
    }

    async fn sock_accept(&mut self, fdflags: FdFlags) -> Result<Box<dyn WasiFile>, Error> {
        self.any.sock_accept(fdflags).await
    }

    async fn datasync(&self) -> Result<(), Error> {
        self.any.datasync().await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.any.sync().await
    }

    async fn get_filetype(&self) -> Result<FileType, Error> {
        self.any.get_filetype().await
    }

    async fn get_fdflags(&self) -> Result<FdFlags, Error> {
        self.any.get_fdflags().await
    }

    async fn set_fdflags(&mut self, fdflags: FdFlags) -> Result<(), Error> {
        self.any.set_fdflags(fdflags).await
    }

    async fn get_filestat(&self) -> Result<Filestat, Error> {
        self.any.get_filestat().await
    }

    async fn set_filestat_size(&self, size: u64) -> Result<(), Error> {
        self.any.set_filestat_size(size).await
    }

    async fn advise(&self, offset: u64, len: u64, advice: Advice) -> Result<(), Error> {
        self.any.advise(offset, len, advice).await
    }

    async fn allocate(&self, offset: u64, len: u64) -> Result<(), Error> {
        self.any.allocate(offset, len).await
    }

    async fn set_times(
        &self,
        atime: Option<wasi_common::SystemTimeSpec>,
        mtime: Option<wasi_common::SystemTimeSpec>,
    ) -> Result<(), Error> {
        self.any.set_times(atime, mtime).await
    }

    async fn read_vectored<'a>(&self, bufs: &mut [IoSliceMut<'a>]) -> Result<u64, Error> {
        self.complete_io()?;

        self.lck
            .write()
            .unwrap()
            .1
            .reader()
            .read_vectored(bufs)
            .map_err(errmap)?
            .try_into()
            .map_err(|e| Error::range().context(e))
    }

    async fn read_vectored_at<'a>(
        &self,
        _bufs: &mut [IoSliceMut<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn write_vectored<'a>(&self, bufs: &[IoSlice<'a>]) -> Result<u64, Error> {
        self.complete_io()?;

        let n = self
            .lck
            .write()
            .unwrap()
            .1
            .writer()
            .write_vectored(bufs)
            .map_err(errmap)?
            .try_into()
            .map_err(|e| Error::range().context(e))?;

        self.complete_io()?;
        Ok(n)
    }

    async fn write_vectored_at<'a>(
        &self,
        _bufs: &[IoSlice<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn seek(&self, pos: std::io::SeekFrom) -> Result<u64, Error> {
        self.any.seek(pos).await
    }

    async fn peek(&self, _buf: &mut [u8]) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn num_ready_bytes(&self) -> Result<u64, Error> {
        self.any.num_ready_bytes().await
    }

    fn isatty(&self) -> bool {
        self.any.isatty()
    }

    async fn readable(&self) -> Result<(), Error> {
        self.any.readable().await
    }

    async fn writable(&self) -> Result<(), Error> {
        self.any.writable().await
    }
}

pub struct Listener {
    cap: Forgotten<CapListener>,
    any: AnyListener,
    cfg: Arc<ServerConfig>,
}

impl Listener {
    pub fn new(tcp: CapListener, cfg: Arc<ServerConfig>) -> Self {
        // Safety: We create a "borrowed" (i.e. `Forgotten`) copy of `CapListener`.
        // The `AnyListener` is the real owner of the file descriptor.
        // This is a workaround until wasmtime 0.36.0 is released.
        let cap = unsafe { CapListener::from_raw_fd(tcp.as_raw_fd()) }.into();
        let any = AnyListener::from_cap_std(tcp);
        Self { cap, any, cfg }
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
        self.any.as_any()
    }

    async fn sock_accept(&mut self, fdflags: FdFlags) -> Result<Box<dyn WasiFile>, Error> {
        // Accept the connection.
        let (cap, ..) = self.cap.accept()?;

        // Create a new TLS connection.
        let tls = Connection::Server(
            ServerConnection::new(self.cfg.clone())
                .map_err(|e| Error::io().context(e))
                .context("could not create new TLS connection")?,
        );

        cap.set_nonblocking(false)?;
        let mut stream = Stream::new(cap, tls);
        stream.complete_io()?;

        stream.set_fdflags(fdflags).await?;
        Ok(Box::new(stream))
    }

    async fn datasync(&self) -> Result<(), Error> {
        self.any.datasync().await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.any.sync().await
    }

    async fn get_filetype(&self) -> Result<FileType, Error> {
        self.any.get_filetype().await
    }

    async fn get_fdflags(&self) -> Result<FdFlags, Error> {
        self.any.get_fdflags().await
    }

    async fn set_fdflags(&mut self, fdflags: FdFlags) -> Result<(), Error> {
        self.any.set_fdflags(fdflags).await
    }

    async fn get_filestat(&self) -> Result<Filestat, Error> {
        self.any.get_filestat().await
    }

    async fn set_filestat_size(&self, size: u64) -> Result<(), Error> {
        self.any.set_filestat_size(size).await
    }

    async fn advise(&self, offset: u64, len: u64, advice: Advice) -> Result<(), Error> {
        self.any.advise(offset, len, advice).await
    }

    async fn allocate(&self, offset: u64, len: u64) -> Result<(), Error> {
        self.any.allocate(offset, len).await
    }

    async fn set_times(
        &self,
        atime: Option<wasi_common::SystemTimeSpec>,
        mtime: Option<wasi_common::SystemTimeSpec>,
    ) -> Result<(), Error> {
        self.any.set_times(atime, mtime).await
    }

    async fn read_vectored<'a>(&self, bufs: &mut [IoSliceMut<'a>]) -> Result<u64, Error> {
        self.any.read_vectored(bufs).await
    }

    async fn read_vectored_at<'a>(
        &self,
        bufs: &mut [IoSliceMut<'a>],
        offset: u64,
    ) -> Result<u64, Error> {
        self.any.read_vectored_at(bufs, offset).await
    }

    async fn write_vectored<'a>(&self, bufs: &[IoSlice<'a>]) -> Result<u64, Error> {
        self.any.write_vectored(bufs).await
    }

    async fn write_vectored_at<'a>(&self, bufs: &[IoSlice<'a>], offset: u64) -> Result<u64, Error> {
        self.any.write_vectored_at(bufs, offset).await
    }

    async fn seek(&self, pos: std::io::SeekFrom) -> Result<u64, Error> {
        self.any.seek(pos).await
    }

    async fn peek(&self, buf: &mut [u8]) -> Result<u64, Error> {
        self.any.peek(buf).await
    }

    async fn num_ready_bytes(&self) -> Result<u64, Error> {
        self.any.num_ready_bytes().await
    }

    fn isatty(&self) -> bool {
        self.any.isatty()
    }

    async fn readable(&self) -> Result<(), Error> {
        self.any.readable().await
    }

    async fn writable(&self) -> Result<(), Error> {
        self.any.writable().await
    }
}
