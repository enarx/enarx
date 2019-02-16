use endicon::Endianness;
use codicon::Decoder;
use std::io::Read;

use super::super::super::{Error, Params};
use super::*;

impl Decoder<Params, Error> for Usage {
    fn decode<R: Read>(reader: &mut R, _: Params) -> Result<Self, Error> {
        Ok(match u32::decode(reader, Endianness::Little)? {
            0x0000 => Usage::AmdRootKey,
            0x0013 => Usage::AmdSevKey,
            u @ _ => Err(Error::InvalidSyntax(format!("usage: {:08X}", u)))?
        })
    }
}

impl Decoder<Params, Error> for Body {
    fn decode<R: Read>(reader: &mut R, params: Params) -> Result<Self, Error> {
        let key_id = u128::decode(reader, Endianness::Little)?;
        let sig_id = u128::decode(reader, Endianness::Little)?;
        let usage = Usage::decode(reader, params)?;
        u128::decode(reader, Endianness::Little)?; // Reserved

        let psize = match u32::decode(reader, Endianness::Little)? {
            2048 => 2048 / 8,
            4096 => 4096 / 8,
            s @ _ => Err(Error::InvalidSyntax(format!("pubexp size: {}", s)))?,
        };

        let msize = match u32::decode(reader, Endianness::Little)? {
            2048 => 2048 / 8,
            4096 => 4096 / 8,
            s @ _ => Err(Error::InvalidSyntax(format!("modulus size: {}", s)))?,
        };
        
        let mut pubexp = vec![0u8; psize];
        reader.read_exact(&mut pubexp)?;
        
        let mut modulus = vec![0u8; msize];
        reader.read_exact(&mut modulus)?;
        
        Ok(Body {
            key_id,
            sig_id,
            usage,
            pubexp,
            modulus,
        })
    }
}

impl Decoder<Params, Error> for Certificate {
    fn decode<R: Read>(reader: &mut R, params: Params) -> Result<Self, Error> {
        let body = Body::decode(reader, params)?;

        let mut signature = vec![0u8; body.modulus.len()];
        reader.read_exact(&mut signature)?;
        
        Ok(Certificate { body, signature })
    }
}
