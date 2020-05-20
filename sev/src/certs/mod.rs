// SPDX-License-Identifier: Apache-2.0

pub mod builtin;
pub mod ca;
mod chain;
pub mod sev;
mod util;

#[cfg(feature = "openssl")]
mod crypto;

use std::convert::*;
use std::io::*;

pub use chain::Chain;

#[allow(unused_imports)]
use util::*;

#[cfg(feature = "openssl")]
use openssl::*;

#[cfg(feature = "openssl")]
struct Body;

#[cfg(feature = "openssl")]
pub trait Verifiable {
    type Output;

    fn verify(self) -> Result<Self::Output>;
}

#[cfg(feature = "openssl")]
pub trait Signer<T> {
    type Output;

    fn sign(&self, target: &mut T) -> Result<Self::Output>;
}

#[cfg(feature = "openssl")]
struct Signature {
    id: Option<u128>,
    sig: Vec<u8>,
    kind: pkey::Id,
    hash: hash::MessageDigest,
    usage: Usage,
}

#[cfg(feature = "openssl")]
pub struct PrivateKey<U> {
    id: Option<u128>,
    key: pkey::PKey<pkey::Private>,
    hash: hash::MessageDigest,
    usage: U,
}

#[cfg(feature = "openssl")]
struct PublicKey<U> {
    id: Option<u128>,
    key: pkey::PKey<pkey::Public>,
    hash: hash::MessageDigest,
    usage: U,
}

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
        write!(
            f,
            "{}",
            match *self {
                Usage::OCA => "OCA",
                Usage::PEK => "PEK",
                Usage::PDH => "PDH",
                Usage::CEK => "CEK",
                Usage::ARK => "ARK",
                Usage::ASK => "ASK",
                Usage::INV => "INV",
                _ => return Err(std::fmt::Error),
            }
        )
    }
}
