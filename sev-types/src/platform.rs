// SPDX-License-Identifier: Apache-2.0

//! The `platform` module contains types that describe various
//! components of the SEV platform (also referred to as the SEV
//! firmware in the API specification).

/// The firmware `Version` is comprised of a major version number
/// and a minor version number.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// The firmware's major version.
    pub major: u8,

    /// The firmware's minor version.
    pub minor: u8,
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The firmware 'Build' is the Build ID for a particular API version.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Build {
    /// The firmware's version.
    pub version: Version,

    ///  Build ID.
    pub build: u8,
}

impl core::fmt::Display for Build {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}.{}", self.version, self.build)
    }
}
