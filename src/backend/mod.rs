// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "backend-kvm")]
pub mod kvm;

#[cfg(feature = "backend-sev")]
pub mod sev;

#[cfg(feature = "backend-sgx")]
pub mod sgx;

mod binary;
mod probe;

use binary::Binary;

use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::{Error, Result};
use mmarinus::{perms, Map};
use sallyport::Block;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use spinning::Lazy;

trait Config: Sized {
    type Flags;

    fn flags(flags: u32) -> Self::Flags;
    fn new(shim: &Binary<'_>, exec: &Binary<'_>) -> Result<Self>;
}

trait Mapper: Sized + TryFrom<Self::Config, Error = Error> {
    type Config: Config;
    type Output: TryFrom<Self, Error = Error>;

    fn map(
        &mut self,
        pages: Map<perms::ReadWrite>,
        to: usize,
        with: <Self::Config as Config>::Flags,
    ) -> Result<()>;
}

trait Loader: Mapper {
    fn load(shim: impl AsRef<[u8]>, exec: impl AsRef<[u8]>) -> Result<Self::Output>;
}

pub trait Backend: Sync + Send {
    /// The name of the backend
    fn name(&self) -> &'static str;

    /// The builtin shim
    fn shim(&self) -> &'static [u8];

    /// The tests that show platform support for the backend
    fn data(&self) -> Vec<Datum>;

    /// Create a keep instance
    fn keep(&self, shim: &[u8], exec: &[u8]) -> Result<Arc<dyn Keep>>;

    /// Hash the inputs
    fn hash(&self, shim: &[u8], exec: &[u8]) -> Result<Vec<u8>>;

    /// Whether or not the platform has support for this keep type
    fn have(&self) -> bool {
        !self.data().iter().fold(false, |e, d| e | !d.pass)
    }
}

impl Serialize for dyn Backend {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut backend = serializer.serialize_struct("Backend", 2)?;
        backend.serialize_field("backend", self.name())?;
        backend.serialize_field("data", &self.data())?;
        backend.end()
    }
}

#[derive(serde::Serialize)]
pub struct Datum {
    /// The name of this datum.
    pub name: String,

    /// Whether the datum indicates support for the platform or not.
    pub pass: bool,

    /// Short additional information to display to the user.
    pub info: Option<String>,

    /// Longer explanatory message on how to resolve problems.
    pub mesg: Option<String>,
}

pub trait Keep {
    /// Creates a new thread in the keep.
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn Thread>>>;
}

pub trait Thread {
    /// Enters the keep.
    fn enter(&mut self) -> Result<Command<'_>>;
}

pub enum Command<'a> {
    #[allow(dead_code)]
    SysCall(&'a mut Block),

    #[allow(dead_code)]
    CpuId(&'a mut Block),

    #[cfg(feature = "gdb")]
    #[allow(dead_code)]
    Gdb(&'a mut Block, &'a mut Option<std::net::TcpStream>),

    #[allow(dead_code)]
    Continue,
}

pub static BACKENDS: Lazy<Vec<Box<dyn Backend>>> = Lazy::new(|| {
    vec![
        #[cfg(feature = "backend-sgx")]
        Box::new(sgx::Backend),
        #[cfg(feature = "backend-sev")]
        Box::new(sev::Backend),
        #[cfg(feature = "backend-kvm")]
        Box::new(kvm::Backend),
    ]
});

#[cfg(feature = "gdb")]
pub fn wait_for_gdb_connection(sockaddr: &str) -> std::io::Result<std::net::TcpStream> {
    use std::net::TcpListener;

    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);
    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;

    // Blocks until a GDB client connects via TCP.
    // i.e: Running `target remote localhost:<port>` from the GDB prompt.

    eprintln!("Debugger connected from {}", addr);
    Ok(stream) // `TcpStream` implements `gdbstub::Connection`
}

#[cfg(feature = "gdb")]
pub fn handle_gdb(block: &mut Block, gdb_fd: &mut Option<std::net::TcpStream>, sockaddr: &str) {
    use gdbstub::Connection;

    let req = unsafe { block.msg.req };
    match req.num.into() {
        sallyport::syscall::SYS_ENARX_GDB_START => {
            if gdb_fd.is_none() {
                let mut stream = wait_for_gdb_connection(sockaddr).unwrap();
                let res = stream
                    .on_session_start()
                    .map(|_| [0usize.into(), 0usize.into()])
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));
                if res.is_ok() {
                    gdb_fd.replace(stream);
                }
                block.msg.rep = res.into();
            } else {
                block.msg.rep = Ok([0usize.into(), 0usize.into()]).into();
            }
        }

        sallyport::syscall::SYS_ENARX_GDB_PEEK => {
            let stream = gdb_fd.as_mut().unwrap();

            let ret = Connection::peek(stream)
                .map(|v| {
                    let v = v.map(|v| v as usize).unwrap_or(u8::MAX as usize + 1);
                    [v.into(), 0usize.into()]
                })
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));
            block.msg.rep = ret.into();
        }

        sallyport::syscall::SYS_ENARX_GDB_READ => {
            let stream = gdb_fd.as_mut().unwrap();

            let buf_ptr: *mut u8 = req.arg[0].into();
            let buf_len: usize = req.arg[1].into();
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len) };

            let ret = stream
                .read_exact(buf)
                .map(|_| [buf_len.into(), 0usize.into()])
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));

            block.msg.rep = ret.into();
        }

        sallyport::syscall::SYS_ENARX_GDB_WRITE => {
            let stream = gdb_fd.as_mut().unwrap();

            let buf_ptr: *mut u8 = req.arg[0].into();
            let buf_len: usize = req.arg[1].into();
            let buf = unsafe { core::slice::from_raw_parts(buf_ptr, buf_len) };

            let ret = Connection::write_all(stream, buf)
                .map(|_| [buf_len.into(), 0usize.into()])
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));
            block.msg.rep = ret.into();
        }

        _ => {}
    }
}
