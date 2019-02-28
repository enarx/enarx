extern crate codicon;
extern crate endicon;

pub mod sev;
pub mod ca;

use std::fmt::{Display, Formatter, Result};
use std::io;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    Invalid(String),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match *self {
            Error::IoError(ref e) => e.fmt(f),
            Error::Invalid(ref s) => write!(f, "invalid: {}", s),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Params;
