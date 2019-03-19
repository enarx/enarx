use std::fmt::{Display, Error, Formatter, Result};
use std::num::NonZeroU128;

use openssl::{hash, pkey, ec, nid};

mod encoders;
mod decoders;
mod common;

#[cfg(test)]
mod naples;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Usage {
    OwnerCertificateAuthority,
    PlatformEndorsementKey,
    PlatformDiffieHellman,
    ChipEndorsementKey,
    AmdRootKey,
    AmdSevKey,
}

struct Signature {
    usage: Usage,
    hash: hash::MessageDigest,
    key: pkey::Id,
    sig: Vec<u8>,
    id: Option<NonZeroU128>,
}

struct PublicKey {
    usage: Usage,
    hash: hash::MessageDigest,
    key: pkey::PKey<pkey::Public>,
    id: Option<NonZeroU128>,
}

pub struct PrivateKey {
    usage: Usage,
    hash: hash::MessageDigest,
    key: pkey::PKey<pkey::Private>,
    id: Option<NonZeroU128>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Firmware(pub u8, pub u8);

pub struct Certificate {
    version: u32,
    firmware: Option<Firmware>,
    key: PublicKey,
    sig: [Option<Signature>; 2],
}

impl Certificate {
    pub fn oca() -> std::io::Result<(Certificate, PrivateKey)> {
        let group = ec::EcGroup::from_curve_name(nid::Nid::SECP384R1)?;

        let private = ec::EcKey::generate(&group)?;
        let public = ec::EcKey::from_public_key(&group, private.public_key())?;

        let private = pkey::PKey::from_ec_key(private)?;
        let public = pkey::PKey::from_ec_key(public)?;

        let mut cert = Certificate {
            firmware: Some(Firmware(0, 0)),
            version: 1,
            sig: [None, None],
            key: PublicKey {
                usage: Usage::OwnerCertificateAuthority,
                hash: hash::MessageDigest::sha256(),
                key: public,
                id: None,
            }
        };

        let key = PrivateKey {
            usage: Usage::OwnerCertificateAuthority,
            hash: hash::MessageDigest::sha256(),
            key: private,
            id: None,
        };

        key.sign(&mut cert)?;

        Ok((cert, key))
    }

    pub fn usage(&self) -> Usage {
        self.key.usage
    }

    pub fn firmware(&self) -> Option<Firmware> {
        self.firmware
    }

    pub fn verify(&self, other: &Certificate) -> std::result::Result<(), ()> {
        if let Some(ref s) = other.sig[0] {
            if self.key.verify(other, s).is_ok() {
                return Ok(());
            }
        }

        if let Some(ref s) = other.sig[1] {
            return self.key.verify(other, s);
        }

        Err(())
    }
}

impl Display for Firmware {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}

impl Display for Usage {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{}", match self {
            Usage::OwnerCertificateAuthority => "OCA",
            Usage::PlatformEndorsementKey => "PEK",
            Usage::PlatformDiffieHellman => "PDH",
            Usage::ChipEndorsementKey => "CEK",
            Usage::AmdRootKey => "ARK",
            Usage::AmdSevKey => "ASK",
        })
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::common::Kind::*;

        match (self.usage.into(), self.key.id()) {
            (Signing, pkey::Id::RSA) => write!(f, "R{} R{}",
                    self.key.rsa()?.size() * 8,
                    self.hash.size() * 8),

            (Signing, pkey::Id::EC)  => write!(f, "EP{} E{}",
                    self.key.ec_key()?.group().degree(),
                    self.hash.size() * 8),

            (Exchange, pkey::Id::EC) => write!(f, "EP{} D{}",
                    self.key.ec_key()?.group().degree(),
                    self.hash.size() * 8),

            _ => Err(Error),
        }
    }
}
