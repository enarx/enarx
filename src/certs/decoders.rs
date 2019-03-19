use endicon::Endianness;
use codicon::Decoder;
use openssl::*;

use std::io::{Error, ErrorKind, Read, Result};
use std::num::NonZeroU128;

use super::common::*;
use super::*;

#[derive(Copy, Clone, Debug)]
struct Sev;

#[derive(Copy, Clone, Debug)]
struct Ca;

impl Decoder<Sev> for Firmware {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: Sev) -> Result<Self> {
        Ok(Firmware(
            u8::decode(reader, Endianness::Little)?,
            u8::decode(reader, Endianness::Little)?,
        ))
    }
}

impl Decoder<Sev> for Option<Usage> {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: Sev) -> Result<Self> {
        Ok(Some(match u32::decode(reader, Endianness::Little)? {
            0x1001 => Usage::OwnerCertificateAuthority,
            0x1002 => Usage::PlatformEndorsementKey,
            0x1003 => Usage::PlatformDiffieHellman,
            0x1004 => Usage::ChipEndorsementKey,
            0x0000 => Usage::AmdRootKey,
            0x0013 => Usage::AmdSevKey,
            0x1000 => return Ok(None),
            _ => return Err(ErrorKind::InvalidData.into()),
        }))
    }
}

impl Decoder<Internal<usize>> for bn::BigNum {
    type Error = Error;

    fn decode(reader: &mut impl Read, params: Internal<usize>) -> Result<Self> {
        let mut buf = vec![0u8; params.0];
        reader.read_exact(&mut buf)?;

        buf.reverse();

        Ok(bn::BigNum::from_slice(&buf)?)
    }
}

impl Decoder<Sev> for rsa::Rsa<pkey::Public> {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: Sev) -> Result<Self> {
        let _ = u32::decode(reader, Endianness::Little)?;
        let e = bn::BigNum::decode(reader, Internal(512))?;
        let n = bn::BigNum::decode(reader, Internal(512))?;
        Ok(rsa::Rsa::from_public_components(n, e)?)
    }
}

impl Decoder<Sev> for ec::EcKey<pkey::Public> {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: Sev) -> Result<Self> {
        let nid = match u32::decode(reader, Endianness::Little)? {
            1 => nid::Nid::X9_62_PRIME256V1,
            2 => nid::Nid::SECP384R1,
            _ => return Err(ErrorKind::InvalidData.into()),
        };

        let g = ec::EcGroup::from_curve_name(nid)?;
        let x = bn::BigNum::decode(reader, Internal(72))?;
        let y = bn::BigNum::decode(reader, Internal(72))?;

        reader.read_exact(&mut [0u8; 880])?; // Reserved

        Ok(ec::EcKey::from_public_key_affine_coordinates(&g, &x, &y)?)
    }
}

impl Decoder<common::Kind> for IdHash {
    type Error = Error;

    fn decode(reader: &mut impl Read, kind: common::Kind) -> Result<Self> {
        use openssl::{hash::MessageDigest as Hash, pkey::Id};
        use super::common::Kind::*;

        Ok(match u32::decode(reader, Endianness::Little)? {
            0x0001 if kind == Signing  => IdHash(Id::RSA, Hash::sha256()),
            0x0002 if kind == Signing  => IdHash(Id::EC,  Hash::sha256()),
            0x0003 if kind == Exchange => IdHash(Id::EC,  Hash::sha256()),
            0x0101 if kind == Signing  => IdHash(Id::RSA, Hash::sha384()),
            0x0102 if kind == Signing  => IdHash(Id::EC,  Hash::sha384()),
            0x0103 if kind == Exchange => IdHash(Id::EC,  Hash::sha384()),
            _ => return Err(ErrorKind::InvalidData.into()),
        })
    }
}

impl Decoder<Sev> for PublicKey {
    type Error = Error;

    fn decode(reader: &mut impl Read, params: Sev) -> Result<Self> {
        let usage: Usage = match Option::decode(reader, params)? {
            None => return Err(ErrorKind::InvalidData.into()),
            Some(u) => u,
        };

        let IdHash(id, hash) = IdHash::decode(reader, usage.into())?;

        let key = match id {
            pkey::Id::RSA => {
                let rsa = rsa::Rsa::decode(reader, params)?;
                pkey::PKey::from_rsa(rsa)?
            },

            pkey::Id::EC => {
                let ecc = ec::EcKey::decode(reader, params)?;
                pkey::PKey::from_ec_key(ecc)?
            },

            _ => return Err(ErrorKind::InvalidData.into()),
        };

        Ok(PublicKey { usage, hash, key, id: None })
    }
}

impl Decoder<Sev> for ecdsa::EcdsaSig {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: Sev) -> Result<Self> {
        let r = bn::BigNum::decode(reader, Internal(72))?;
        let s = bn::BigNum::decode(reader, Internal(72))?;

        reader.read_exact(&mut [0u8; 368])?; // Reserved

        Ok(ecdsa::EcdsaSig::from_private_components(r, s)?)
    }
}

impl Decoder<Sev> for Option<Signature> {
    type Error = Error;

    fn decode(reader: &mut impl Read, params: Sev) -> Result<Self> {
        let usage: Usage = match Option::decode(reader, params)? {
            None => { reader.read_exact(&mut [0u8; 516])?; return Ok(None) },
            Some(u) => u,
        };

        let IdHash(key, hash) = IdHash::decode(reader, usage.into())?;

        let sig = match key {
            pkey::Id::RSA => bn::BigNum::decode(reader, Internal(512))?.to_vec(),
            pkey::Id::EC => ecdsa::EcdsaSig::decode(reader, params)?.to_der()?,
            _ => return Err(ErrorKind::InvalidData.into()),
        };

        Ok(Some(Signature { usage, hash, key, sig, id: None }))
    }
}

impl Decoder<Sev> for Certificate {
    type Error = Error;

    fn decode(reader: &mut impl Read, params: Sev) -> Result<Self> {
        let ver = u32::decode(reader, Endianness::Little)?;
        if ver != 1 { return Err(ErrorKind::InvalidData.into()) }

        let firmware = Some(Firmware::decode(reader, params)?);
        u16::decode(reader, Endianness::Little)?; // Reserved

        Ok(Certificate {
            version: ver,
            firmware,
            key: PublicKey::decode(reader, params)?,
            sig: [
                Option::decode(reader, params)?,
                Option::decode(reader, params)?
            ]
        })
    }
}

impl Decoder<Ca> for Option<NonZeroU128> {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: Ca) -> Result<Self> {
        Ok(NonZeroU128::new(u128::decode(reader, Endianness::Little)?))
    }
}

impl Decoder<Ca> for Usage {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: Ca) -> Result<Self> {
        Ok(match u32::decode(reader, Endianness::Little)? {
            0x0000 => Usage::AmdRootKey,
            0x0013 => Usage::AmdSevKey,
            _ => return Err(ErrorKind::InvalidData.into()),
        })
    }
}

impl Decoder<Ca> for rsa::Rsa<pkey::Public> {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: Ca) -> Result<Self> {
        let psize = match u32::decode(reader, Endianness::Little)? {
            2048 => 256,
            4096 => 512,
            _ => return Err(ErrorKind::InvalidData.into()),
        };

        let msize = match u32::decode(reader, Endianness::Little)? {
            2048 => 256,
            4096 => 512,
            _ => return Err(ErrorKind::InvalidData.into()),
        };

        let e = bn::BigNum::decode(reader, Internal(psize))?;
        let n = bn::BigNum::decode(reader, Internal(msize))?;
        Ok(rsa::Rsa::from_public_components(n, e)?)
    }
}

impl Decoder<Ca> for Certificate {
    type Error = Error;

    fn decode(reader: &mut impl Read, params: Ca) -> Result<Self> {
        let ver = u32::decode(reader, Endianness::Little)?;
        if ver != 1 { return Err(ErrorKind::InvalidData.into()) }

        let kid = Option::decode(reader, params)?;
        let cid = Option::decode(reader, params)?;
        let usage = Usage::decode(reader, params)?;
        u128::decode(reader, Endianness::Little)?; // Reserved
        let rsa = rsa::Rsa::decode(reader, params)?;
        let sig = bn::BigNum::decode(reader, Internal(rsa.size() as usize))?;

        Ok(Certificate {
            firmware: None,
            version: ver,
            key: PublicKey {
                hash: hash::MessageDigest::sha256(),
                id: kid,
                key: pkey::PKey::from_rsa(rsa)?,
                usage,
            },
            sig: [
                Some(Signature {
                    usage: Usage::AmdRootKey,
                    hash: hash::MessageDigest::sha256(),
                    key: pkey::Id::RSA,
                    sig: sig.to_vec(),
                    id: cid,
                }),
                None
            ]
        })
    }
}

impl Usage {
    pub fn load(self, reader: &mut impl Read) -> Result<Certificate> {
        let crt = match self {
            Usage::OwnerCertificateAuthority |
            Usage::PlatformEndorsementKey |
            Usage::PlatformDiffieHellman |
            Usage::ChipEndorsementKey => Certificate::decode(reader, Sev)?,

            Usage::AmdRootKey |
            Usage::AmdSevKey => Certificate::decode(reader, Ca)?,
        };

        if crt.key.usage == self {
            Ok(crt)
        } else {
            Err(ErrorKind::InvalidData.into())
        }
    }
}

impl Certificate {
    pub fn load(&self, reader: &mut impl Read) -> Result<PrivateKey> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let key = pkey::PKey::private_key_from_der(&buf)?;

        Ok(PrivateKey {
            usage: self.key.usage,
            hash: self.key.hash,
            id: self.key.id,
            key
        })
    }
}
