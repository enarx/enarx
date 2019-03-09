mod encoders;
mod decoders;
mod verify;

#[cfg(test)]
mod naples;

trait EncodeBuf<T>: codicon::Encoder<T> {
    fn encode_buf(&self, params: T) -> Result<Vec<u8>, Self::Error> {
        let mut buf = Vec::new();
        self.encode(&mut buf, params)?;
        Ok(buf)
    }
}

impl<T, U: codicon::Encoder<T>> EncodeBuf<T> for U {}

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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Usage {
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
enum Curve {
    P256,
    P384,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EccKey {
    curve: Curve,
    x: Vec<u8>,
    y: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Key {
    Rsa(RsaKey),
    Ecc(EccKey),
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
pub struct Firmware(pub u8, pub u8);

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

pub trait Verifier<'a> {
    fn verify(self) -> Result<&'a Certificate, ()>;
}

#[derive(Copy, Clone, Debug)]
struct Ring;

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

impl PartialEq<SigAlgo> for Algo {
    fn eq(&self, other: &SigAlgo) -> bool {
        *self == Algo::from(*other)
    }
}

impl PartialEq<ExcAlgo> for Algo {
    fn eq(&self, other: &ExcAlgo) -> bool {
        *self == Algo::from(*other)
    }
}

impl Curve {
    fn size(&self) -> usize {
        match self {
            Curve::P256 => 256 / 8,
            Curve::P384 => 384 / 8,
        }
    }
}

impl Certificate {
    pub fn firmware(&self) -> Option<Firmware> {
        self.firmware
    }

    pub fn usage(&self) -> Usage {
        self.key.usage
    }
}
