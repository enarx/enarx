pub mod sev;
pub mod ca;
mod chain;
mod util;

#[cfg(feature = "openssl")]
mod crypto;

#[cfg(test)]
mod naples;

use std::convert::*;
use std::io::*;

pub use chain::Chain;

#[allow(unused_imports)]
use util::*;

#[cfg(feature = "openssl")]
use crypto::*;

#[cfg(feature = "openssl")]
pub use crypto::{PrivateKey, Signer, Verifiable};

#[cfg(feature = "openssl")]
use openssl::*;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Usage(u32);

impl Usage {
    pub const OCA: Usage = Usage(0x1001u32.to_le());
    pub const ARK: Usage = Usage(0x0000u32.to_le());
    pub const ASK: Usage = Usage(0x0013u32.to_le());
    pub const CEK: Usage = Usage(0x1004u32.to_le());
    pub const PEK: Usage = Usage(0x1002u32.to_le());
    pub const PDH: Usage = Usage(0x1003u32.to_le());
    const INV: Usage = Usage(0x1000u32.to_le());
}

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", match *self {
            Usage::OCA => "OCA",
            Usage::PEK => "PEK",
            Usage::PDH => "PDH",
            Usage::CEK => "CEK",
            Usage::ARK => "ARK",
            Usage::ASK => "ASK",
            Usage::INV => "INV",
            _ => Err(std::fmt::Error)?,
        })
    }
}
