use endicon::Endianness;
use codicon::Decoder;
use std::io::Read;

use super::super::super::{Error, Params};
use super::*;

impl Decoder<Params, Error> for Option<Usage> {
    fn decode<R: Read>(reader: &mut R, _: Params) -> Result<Self, Error> {
        Ok(Some(match u32::decode(reader, Endianness::Little)? {
            0x1001 => Usage::OwnerCertificateAuthority,
            0x1002 => Usage::PlatformEndorsementKey,
            0x1003 => Usage::PlatformDiffieHellman,
            0x1004 => Usage::ChipEndorsementKey,
            0x0000 => Usage::AmdRootKey,
            0x0013 => Usage::AmdSevKey,
            0x1000 => return Ok(None),
            u @ _ => Err(Error::InvalidSyntax(format!("usage: {:08X}", u)))?
        }))
    }
}

impl Decoder<Params, Error> for Option<Algorithm> {
    fn decode<R: Read>(reader: &mut R, _: Params) -> Result<Self, Error> {
        Ok(Some(match u32::decode(reader, Endianness::Little)? {
            0x0000 => return Ok(None),
            0x0001 => Algorithm::RsaSha256,
            0x0002 => Algorithm::EcdsaSha256,
            0x0003 => Algorithm::EcdhSha256,
            0x0101 => Algorithm::RsaSha384,
            0x0102 => Algorithm::EcdsaSha384,
            0x0103 => Algorithm::EcdhSha384,
            a @ _ => Err(Error::InvalidSyntax(format!("algorithm: {:08X}", a)))?
        }))
    }
}

impl Decoder<Params, Error> for Version {
    fn decode<R: Read>(reader: &mut R, _: Params) -> Result<Self, Error> {
        Ok(Version(
            u8::decode(reader, Endianness::Little)?,
            u8::decode(reader, Endianness::Little)?,
        ))
    }
}

impl Decoder<Params, Error> for PublicKey {
    fn decode<R: Read>(reader: &mut R, params: Params) -> Result<Self, Error> {
        let usage = match Option::decode(reader, params)? {
            None => Err(Error::InvalidSyntax("public key invalid usage".to_string()))?,
            Some(u) => u,
        };

        let algo = match Option::decode(reader, params)? {
            None => Err(Error::InvalidSyntax("public key invalid algorithm".to_string()))?,
            Some(a) => a,
        };
        
        let mut key = vec![0u8; 1028];
        reader.read_exact(&mut &mut key[..])?;
        
        Ok(PublicKey { usage, algo, key })
    }
}

impl Decoder<Params, Error> for Option<Signature> {
    fn decode<R: Read>(reader: &mut R, params: Params) -> Result<Self, Error> {
        let usage = Option::decode(reader, params)?;
        let algo = Option::decode(reader, params)?;
        
        let mut sig = vec![0u8; 512];
        reader.read_exact(&mut &mut sig[..])?;
        
        if let Some(usage) = usage {
            if let Some(algo) = algo {
                return Ok(Some(Signature { usage, algo, sig }));
            }
        }
        
        Ok(None)
    }
}

impl Decoder<Params, Error> for Body {
    fn decode<R: Read>(reader: &mut R, params: Params) -> Result<Self, Error> {
        let version = Version::decode(reader, params)?;
        u8::decode(reader, Endianness::Little)?; // Reserved
        u8::decode(reader, Endianness::Little)?; // Reserved
        let pubkey = PublicKey::decode(reader, params)?;
        
        Ok(Body { version, pubkey })
    }
}

impl Decoder<Params, Error> for Certificate {
    fn decode<R: Read>(reader: &mut R, params: Params) -> Result<Self, Error> {
        let body = Body::decode(reader, params)?;
        let sig1 = Option::decode(reader, params)?;
        let sig2 = Option::decode(reader, params)?;
        Ok(Certificate { body, sig1, sig2 })
    }
}
