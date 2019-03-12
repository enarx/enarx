mod encoders;
mod decoders;
mod crypto;

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

#[derive(Copy, Clone)]
struct RsaKey {
    pubexp: [u8; 4096 / 8],
    modulus: [u8; 4096 / 8],
}

impl std::cmp::Eq for RsaKey {}
impl std::cmp::PartialEq for RsaKey {
    fn eq(&self, other: &RsaKey) -> bool {
        self.pubexp[..] == other.pubexp[..]
            && self.modulus[..] == other.modulus[..]
    }
}

impl std::fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "RsaKey {{ pubexp: {:?}, modulus: {:?} }}",
            self.pubexp.to_vec(), self.modulus.to_vec())
    }
}

impl RsaKey {
    fn psize(&self) -> Result<usize, Error> {
        Ok(match self.pubexp.iter().rev().skip_while(|b| **b == 0).count() * 8 {
            0000 ... 2048 => 2048,
            2049 ... 4096 => 4096,
            s => Err(Error::Invalid(format!("pubexp size: {}", s)))?,
        } / 8)
    }

    fn msize(&self) -> Result<usize, Error> {
        Ok(match self.pubexp.iter().rev().skip_while(|b| **b == 0).count() * 8 {
            0000 ... 2048 => 2048,
            2049 ... 4096 => 4096,
            s => Err(Error::Invalid(format!("modulus size: {}", s)))?,
        } / 8)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Curve {
    P256,
    P384,
}

#[derive(Copy, Clone)]
struct EccKey {
    c: Curve,
    x: [u8; 576 / 8],
    y: [u8; 576 / 8],
}

impl std::cmp::Eq for EccKey {}
impl std::cmp::PartialEq for EccKey {
    fn eq(&self, other: &EccKey) -> bool {
        self.x[..] == other.x[..] && self.y[..] == other.y[..]
    }
}

impl std::fmt::Debug for EccKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "EccKey {{ c: {:?}, x: {:?}, y: {:?} }}",
            self.c, self.x.to_vec(), self.y.to_vec())
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Key {
    Rsa(RsaKey),
    Ecc(EccKey),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct PublicKey {
    usage: Usage,
    algo: Algo,
    key: Key,
    id: Option<std::num::NonZeroU128>,
}

#[derive(Copy, Clone)]
struct Signature {
    usage: Usage,
    algo: SigAlgo,
    sig: [u8; 4096 / 8],
    id: Option<std::num::NonZeroU128>,
}

impl std::cmp::Eq for Signature {}
impl std::cmp::PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.usage == other.usage
            && self.algo == other.algo
            && self.sig[..] == other.sig[..]
            && self.id == other.id
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "Signature {{ usage: {:?}, algo: {:?}, sig: {:?}, id: {:?} }}",
            self.usage, self.algo, self.sig.to_vec(), self.id)
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Firmware(pub u8, pub u8);

impl std::fmt::Display for Firmware {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}

#[derive(Copy, Clone, Debug, Eq)]
pub struct Certificate {
    version: u32,
    firmware: Option<Firmware>,
    key: PublicKey,
    sigs: [Option<Signature>; 2],
}

impl Certificate {
    pub fn firmware(&self) -> Option<Firmware> {
        self.firmware
    }

    pub fn usage(&self) -> Usage {
        self.key.usage
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Certificate) -> bool {
        self.version == other.version
            && self.firmware() == other.firmware()
            && self.key == other.key
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Kind {
    Sev,
    Ca
}

pub trait Verifier<'a> {
    fn verify(self) -> Result<&'a Certificate, ()>;
}
