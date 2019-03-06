#![allow(unknown_lints)]
#![warn(clippy)]

extern crate codicon;
extern crate endicon;

mod encoders;
mod decoders;

#[cfg(test)]
mod naples;

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    Invalid(String),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::IoError(ref e) => e.fmt(f),
            Error::Invalid(ref s) => write!(f, "invalid: {}", s),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Usage {
    OwnerCertificateAuthority,
    PlatformEndorsementKey,
    PlatformDiffieHellman,
    ChipEndorsementKey,
    AmdRootKey,
    AmdSevKey,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SigAlgo {
    RsaSha256,
    EcdsaSha256,
    RsaSha384,
    EcdsaSha384,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ExcAlgo {
    EcdhSha256,
    EcdhSha384,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Algo {
    Sig(SigAlgo),
    Exc(ExcAlgo),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RsaKey {
    pubexp: Vec<u8>,
    modulus: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EccKey {
    x: Vec<u8>,
    y: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Key {
    Rsa(RsaKey),
    P256(EccKey),
    P384(EccKey),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicKey {
    usage: Usage,
    algo: Algo,
    key: Key,
    id: Option<std::num::NonZeroU128>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Signature {
    usage: Usage,
    algo: SigAlgo,
    sig: Vec<u8>,
    id: Option<std::num::NonZeroU128>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Firmware {
    major: u8,
    minor: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    version: u32,
    firmware: Option<Firmware>,
    key: PublicKey,
    sigs: Vec<Signature>,
}

#[derive(Copy, Clone, Debug)]
pub enum Kind {
    Sev,
    Ca
}

impl From<SigAlgo> for Algo {
    fn from(value: SigAlgo) -> Algo {
        Algo::Sig(value)
    }
}

impl From<ExcAlgo> for Algo {
    fn from(value: ExcAlgo) -> Algo {
        Algo::Exc(value)
    }
}
