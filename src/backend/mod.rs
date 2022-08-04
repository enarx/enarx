// SPDX-License-Identifier: Apache-2.0

#[cfg(enarx_with_shim)]
pub mod kvm;

#[cfg(enarx_with_shim)]
pub mod sev;

#[cfg(enarx_with_shim)]
pub mod sgx;

pub mod nil;

#[cfg(enarx_with_shim)]
mod binary;

#[cfg(enarx_with_shim)]
mod probe;

#[cfg(enarx_with_shim)]
use binary::{Binary, Loader, Mapper};

use std::fs::File;
use std::io::Read;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
#[cfg(windows)]
use enarx_exec_wasmtime::Args;
use libc::c_int;
use once_cell::sync::Lazy;
use serde::ser::{Serialize, SerializeStruct, Serializer};

#[cfg(not(enarx_with_shim))]
#[allow(dead_code)]
pub struct Binary<'a> {
    phantom: std::marker::PhantomData<&'a ()>,
}

pub const SIGNATURES_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
pub struct SevSignature {
    pub id_block: Vec<u8>,
    pub id_auth: Vec<u8>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Signatures {
    pub version: String,
    pub sev: SevSignature,
    pub sgx: Vec<u8>,
}

impl Default for Signatures {
    fn default() -> Self {
        Self {
            version: SIGNATURES_VERSION.into(),
            sev: SevSignature::default(),
            sgx: vec![],
        }
    }
}

impl Signatures {
    pub fn load(path: Option<Utf8PathBuf>) -> anyhow::Result<Option<Self>> {
        match path {
            None => Ok(None),
            Some(path) => {
                let mut file = File::open(path).context("Failed to open hashes file")?;
                let mut buffer = String::new();
                file.read_to_string(&mut buffer)?;
                let ret = serde_json::from_str::<Signatures>(&buffer)
                    .context("serde_json")
                    .map(Some);
                if let Ok(Some(Signatures { ref version, .. })) = ret {
                    if version != SIGNATURES_VERSION {
                        bail!(
                            "Signature file version {} does not match current version {}",
                            version,
                            SIGNATURES_VERSION
                        );
                    }
                }
                ret
            }
        }
    }
}

/// A trait for types that can be serialized and deserialized to/from a byte slice.
///
/// # Safety
///
/// Behavior is undefined if Self is initialized with bytes, which do not represent a valid state.
pub unsafe trait ByteSized: Sized {
    /// The constant default value.
    const SIZE: usize = std::mem::size_of::<Self>();

    /// Create Self from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }

        Some(unsafe { (bytes.as_ptr() as *const _ as *const Self).read_unaligned() })
    }

    /// Serialize Self to a byte slice.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: This is safe because we know that the pointer is non-null and the length is correct
        // and u8 does not need any alignment.
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, Self::SIZE) }
    }
}

pub(crate) trait Config: Sized {
    type Flags;

    fn flags(flags: u32) -> Self::Flags;
    fn new(shim: &Binary<'_>, exec: &Binary<'_>, signatures: Option<Signatures>) -> Result<Self>;
}

pub trait Backend: Sync + Send {
    /// The name of the backend
    fn name(&self) -> &'static str;

    /// The builtin shim
    fn shim(&self) -> &'static [u8];

    /// The tests that show platform support for the backend
    fn data(&self) -> Vec<Datum>;

    /// The tests that show machine configuration support for the backend
    fn config(&self) -> Vec<Datum>;

    /// Create a keep instance
    fn keep(
        &self,
        shim: &[u8],
        exec: &[u8],
        signatures: Option<Signatures>,
    ) -> Result<Arc<dyn Keep>>;

    /// Hash the inputs
    fn hash(&self, shim: &[u8], exec: &[u8]) -> Result<Vec<u8>>;

    /// Whether or not the platform has support for this keep type
    fn have(&self) -> bool {
        !self.data().iter().fold(false, |e, d| e | !d.pass)
    }

    /// Whether or not the machine is correctly configured for this keep type
    fn configured(&self) -> bool {
        !self.config().iter().fold(false, |e, d| e | !d.pass)
    }

    #[cfg(windows)]
    /// set wasmtime args directly
    fn set_args(&self, _args: Args) {}
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
    fn enter(&mut self, gdblisten: &Option<String>) -> Result<Command>;
}

pub enum Command {
    #[allow(dead_code)]
    Continue,
    Exit(c_int),
}

struct NotSupportedBackend(&'static str);

impl Backend for NotSupportedBackend {
    fn name(&self) -> &'static str {
        self.0
    }

    fn shim(&self) -> &'static [u8] {
        &[]
    }

    fn data(&self) -> Vec<Datum> {
        vec![]
    }

    fn config(&self) -> Vec<Datum> {
        vec![]
    }

    #[inline]
    fn have(&self) -> bool {
        false
    }

    #[inline]
    fn configured(&self) -> bool {
        false
    }

    fn keep(
        &self,
        _shim: &[u8],
        _exec: &[u8],
        _signatures: Option<Signatures>,
    ) -> Result<Arc<dyn Keep>> {
        unimplemented!()
    }

    fn hash(&self, _shim: &[u8], _exec: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
}

pub static BACKENDS: Lazy<Vec<Box<dyn Backend>>> = Lazy::new(|| {
    vec![
        #[cfg(enarx_with_shim)]
        Box::new(sgx::Backend),
        #[cfg(not(enarx_with_shim))]
        Box::new(NotSupportedBackend("sgx")),
        #[cfg(enarx_with_shim)]
        Box::new(sev::Backend),
        #[cfg(not(enarx_with_shim))]
        Box::new(NotSupportedBackend("sev")),
        #[cfg(enarx_with_shim)]
        Box::new(kvm::Backend),
        #[cfg(not(enarx_with_shim))]
        Box::new(NotSupportedBackend("kvm")),
        Box::new(nil::Backend::default()),
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
pub(super) unsafe fn execute_gdb(
    gdbcall: &mut sallyport::item::Gdbcall,
    data: &mut [u8],
    gdb_fd: &mut Option<std::net::TcpStream>,
    sockaddr: &str,
) -> Result<(), c_int> {
    use gdbstub::Connection;
    use sallyport::host::deref_slice;
    use sallyport::item;
    use sallyport::item::gdbcall::Number;

    match gdbcall {
        item::Gdbcall {
            num: Number::OnSessionStart,
            ret,
            ..
        } => {
            if gdb_fd.is_none() {
                let mut stream = wait_for_gdb_connection(sockaddr).unwrap();

                let res = stream
                    .on_session_start()
                    .map(|_| 0usize)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));

                if res.is_ok() {
                    gdb_fd.replace(stream);
                }

                *ret = match res {
                    Ok(n) => n as usize,
                    Err(e) => -e as usize,
                };
            } else {
                *ret = 0;
            }
            Ok(())
        }

        item::Gdbcall {
            num: Number::Flush,
            ret,
            ..
        } => {
            let stream = gdb_fd.as_mut().unwrap();

            let res = Connection::flush(stream)
                .map(|_| 0)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));

            *ret = match res {
                Ok(n) => n as usize,
                Err(e) => -e as usize,
            };
            Ok(())
        }

        item::Gdbcall {
            num: Number::Peek,
            ret,
            ..
        } => {
            let stream = gdb_fd.as_mut().unwrap();

            let res = Connection::peek(stream)
                .map(|v| v.map(|v| v as usize).unwrap_or(u8::MAX as usize + 1))
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));
            *ret = match res {
                Ok(n) => n,
                Err(e) => -e as usize,
            };
            Ok(())
        }

        item::Gdbcall {
            num: Number::Read,
            ret,
            ..
        } => {
            let stream = gdb_fd.as_mut().unwrap();

            let res =
                Connection::read(stream).map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));

            *ret = match res {
                Ok(n) => n as usize,
                Err(e) => -e as usize,
            };
            Ok(())
        }

        item::Gdbcall {
            num: Number::Write,
            argv: [byte, ..],
            ret,
        } => {
            let stream = gdb_fd.as_mut().unwrap();

            let res = Connection::write(stream, *byte as _)
                .map(|_| 0usize)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));
            *ret = match res {
                Ok(n) => n as usize,
                Err(e) => -e as usize,
            };
            Ok(())
        }

        item::Gdbcall {
            num: Number::WriteAll,
            argv: [buf_offset, count, ..],
            ret,
        } => {
            let stream = gdb_fd.as_mut().unwrap();

            let buf = &*deref_slice::<u8>(data, *buf_offset, *count).unwrap();

            let res = Connection::write_all(stream, buf)
                .map(|_| buf.len())
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL));

            *ret = match res {
                Ok(n) => n as usize,
                Err(e) => -e as usize,
            };
            Ok(())
        }
    }
}
