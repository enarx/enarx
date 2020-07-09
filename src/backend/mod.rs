// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::path::PathBuf;
use std::sync::Arc;

use sallyport::Block;

use super::binary::Component;

pub trait Backend {
    /// Whether or not the platform has support for this keep type
    fn have(&self) -> bool {
        !self.data().iter().fold(false, |e, d| e | !d.pass)
    }

    /// The tests that show platform support for the backend
    fn data(&self) -> Vec<Datum>;

    /// Returns the path for the shim
    fn shim(&self) -> Result<PathBuf>;

    /// Create a keep instance on this backend
    fn build(&self, shim: Component, code: Component) -> Result<Arc<dyn Keep>>;
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
    fn add_thread(self: Arc<Self>) -> Result<Box<dyn Thread>>;
}

pub trait Thread {
    /// Enters the keep.
    fn enter(&mut self) -> Result<Command>;
}

pub enum Command<'a> {
    SysCall(&'a mut Block),
}
