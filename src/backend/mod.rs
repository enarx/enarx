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

trait Config: Sized {
    type Flags;

    fn flags(flags: u32) -> Self::Flags;
    fn new(shim: &Binary, exec: &Binary) -> Result<Self>;
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

pub trait Backend {
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
    fn enter(&mut self) -> Result<Command>;
}

pub enum Command<'a> {
    #[allow(dead_code)]
    SysCall(&'a mut Block),

    #[allow(dead_code)]
    CpuId(&'a mut Block),

    #[allow(dead_code)]
    Continue,
}
