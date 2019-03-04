use endicon::Endianness;
use codicon::Decoder;
use std::io::Read;

use super::super::{Error, Params};
use super::*;

impl Decoder<Params> for Usage {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: Params) -> Result<Self, Error> {
        Ok(match u32::decode(reader, Endianness::Little)? {
            0x0000 => Usage::AmdRootKey,
            0x0013 => Usage::AmdSevKey,
            u @ _ => Err(Error::Invalid(format!("usage: {:08X}", u)))?
        })
    }
}

impl Decoder<Params> for Body1 {
    type Error = Error;
    fn decode(reader: &mut impl Read, params: Params) -> Result<Self, Error> {
        let key_id = u128::decode(reader, Endianness::Little)?;
        let sig_id = u128::decode(reader, Endianness::Little)?;
        let usage = Usage::decode(reader, params)?;
        u128::decode(reader, Endianness::Little)?; // Reserved

        let psize = match u32::decode(reader, Endianness::Little)? {
            2048 => 2048 / 8,
            4096 => 4096 / 8,
            s @ _ => Err(Error::Invalid(format!("pubexp size: {}", s)))?,
        };

        let msize = match u32::decode(reader, Endianness::Little)? {
            2048 => 2048 / 8,
            4096 => 4096 / 8,
            s @ _ => Err(Error::Invalid(format!("modulus size: {}", s)))?,
        };

        let mut pubexp = vec![0u8; psize];
        reader.read_exact(&mut pubexp)?;

        let mut modulus = vec![0u8; msize];
        reader.read_exact(&mut modulus)?;

        let mut signature = vec![0u8; msize];
        reader.read_exact(&mut signature)?;

        Ok(Body1 {
            key_id,
            sig_id,
            usage,
            pubexp,
            modulus,
            signature,
        })
    }
}

impl Decoder<Params> for Versioned {
    type Error = Error;
    fn decode(reader: &mut impl Read, params: Params) -> Result<Self, Error> {
        Ok(match u32::decode(reader, Endianness::Little)? {
            1 => Versioned::Version1(Body1::decode(reader, params)?),
            v @ _ => Err(Error::Invalid(format!("version: {}", v)))?
        })
    }
}

impl Decoder for Certificate {
    type Error = Error;
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, Error> {
        Ok(Certificate(Versioned::decode(reader, Params { omit_sigs: false })?))
    }
}
