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

#[cfg(feature = "openssl")]
use certs::sev;
use certs::{builtin, ca};

#[cfg(feature = "openssl")]
use std::convert::TryFrom;

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

pub enum Generation {
    Naples,
    Rome,
}

impl From<Generation> for ca::Chain {
    fn from(generation: Generation) -> ca::Chain {
        use codicon::Decoder;

        let (ark, ask) = match generation {
            Generation::Naples => (builtin::naples::ARK, builtin::naples::ASK),
            Generation::Rome => (builtin::rome::ARK, builtin::rome::ASK),
        };

        ca::Chain {
            ask: ca::Certificate::decode(&mut &ask[..], ()).unwrap(),
            ark: ca::Certificate::decode(&mut &ark[..], ()).unwrap(),
        }
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&sev::Chain> for Generation {
    type Error = ();

    fn try_from(schain: &sev::Chain) -> Result<Self, Self::Error> {
        use crate::certs::Verifiable;

        let naples: ca::Chain = Generation::Naples.into();
        let rome: ca::Chain = Generation::Rome.into();

        Ok(if (&naples.ask, &schain.cek).verify().is_ok() {
            Generation::Naples
        } else if (&rome.ask, &schain.cek).verify().is_ok() {
            Generation::Rome
        } else {
            return Err(());
        })
    }
}
