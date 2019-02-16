use endicon::Endianness;
use codicon::Decoder;
use std::io::Read;

use super::super::{Error, Params};
use super::*;

impl Decoder<Params, Error> for Certificate {
    fn decode<R: Read>(reader: &mut R, params: Params) -> Result<Self, Error> {
        Ok(match u32::decode(reader, Endianness::Little)? {
            1 => Certificate::Version1(v1::Certificate::decode(reader, params)?),
            v @ _ => Err(Error::InvalidSyntax(format!("version: {}", v)))?
        })
    }
}
