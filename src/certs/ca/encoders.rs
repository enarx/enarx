use endicon::Endianness;
use codicon::Encoder;
use std::io::Write;

use super::super::{Error, Params};
use super::*;

impl Encoder<Params, Error> for Usage {
    fn encode<W: Write>(&self, writer: &mut W, _: Params) -> Result<(), Error> {
        match self {
            Usage::AmdRootKey => 0x0000u32,
            Usage::AmdSevKey => 0x0013u32,
        }.encode(writer, Endianness::Little)?;
        Ok(())
    }
}

impl Encoder<Params, Error> for Body1 {
    fn encode<W: Write>(&self, writer: &mut W, params: Params) -> Result<(), Error> {
        if self.modulus.len() != self.signature.len() {
            let msg = format!("signature size: {}", self.signature.len());
            return Err(Error::InvalidSyntax(msg))?;
        }

        let psize = match self.pubexp.len() {
            256 => 2048u32,
            512 => 4096u32,
            s @ _ => Err(Error::InvalidSyntax(format!("pubexp size: {}", s * 8)))?,
        };

        let msize = match self.modulus.len() {
            256 => 2048u32,
            512 => 4096u32,
            s @ _ => Err(Error::InvalidSyntax(format!("modulus size: {}", s * 8)))?,
        };

        self.key_id.encode(writer, Endianness::Little)?;
        self.sig_id.encode(writer, Endianness::Little)?;
        self.usage.encode(writer, params)?;
        0u128.encode(writer, Endianness::Little)?;

        psize.encode(writer, Endianness::Little)?;
        msize.encode(writer, Endianness::Little)?;

        writer.write_all(&self.pubexp)?;
        writer.write_all(&self.modulus)?;
        writer.write_all(&self.signature)?;

        Ok(())
    }
}

impl Encoder<Params, Error> for Versioned {
    fn encode<W: Write>(&self, writer: &mut W, params: Params) -> Result<(), Error> {
        match self {
            Versioned::Version1(ref body) => {
                1u32.encode(writer, Endianness::Little)?;
                body.encode(writer, params)
            }
        }
    }
}

impl Encoder<Params, Error> for Certificate {
    fn encode<W: Write>(&self, writer: &mut W, params: Params) -> Result<(), Error> {
        self.0.encode(writer, params)
    }
}
