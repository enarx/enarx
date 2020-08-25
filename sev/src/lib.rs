// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
#![allow(unknown_lints)]
#![allow(clippy::identity_op)]
#![allow(clippy::unreadable_literal)]
// TODO: https://github.com/enarx/enarx/issues/347
#![deny(missing_docs)]
#![allow(missing_docs)]

pub mod certs;
pub mod firmware;
pub mod launch;
#[cfg(feature = "openssl")]
pub mod session;
mod util;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Build {
    pub version: Version,
    pub build: u8,
}

impl std::fmt::Display for Build {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.version, self.build)
    }
}
