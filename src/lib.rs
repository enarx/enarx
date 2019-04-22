#![warn(clippy::all)]
#![allow(unknown_lints)]
#![allow(clippy::unreadable_literal)]

#[cfg(feature = "openssl")]
pub mod session;
pub mod launch;
pub mod certs;
pub mod fwapi;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl Version {
    fn new(major: u8, minor: u8) -> Version {
        Version { major, minor }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Build {
    pub version: Version,
    pub build: u8,
}

impl Build {
    fn new(major: u8, minor: u8, build: u8) -> Build {
        Build { version: Version::new(major, minor), build }
    }
}

impl std::fmt::Display for Build {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.version, self.build)
    }
}
