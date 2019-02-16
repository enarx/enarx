use endicon::Endianness;
use codicon::Encoder;
use std::io::Write;

use super::super::{Error, Params};
use super::*;

impl Encoder<Params, Error> for Certificate {
    fn encode<W: Write>(&self, writer: &mut W, params: Params) -> Result<(), Error> {
        match self {
            Certificate::Version1(ref c) => {
                1u32.encode(writer, Endianness::Little)?;
                c.encode(writer, params)
            }
        }
    }
}
