#![warn(clippy::all)]
#![allow(unknown_lints)]
#![allow(clippy::unreadable_literal)]

pub mod certs;
pub mod fwapi;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Firmware(pub u8, pub u8);

impl std::fmt::Display for Firmware {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}
