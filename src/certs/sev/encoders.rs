use endicon::Endianness;
use codicon::Encoder;
use std::io::Write;

use super::super::{Error, Params};
use super::*;

impl Encoder<Params> for Option<Usage> {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Params) -> Result<(), Error> {
        match self {
            None => 0x1000u32,
            Some(ref u) => match u {
                Usage::OwnerCertificateAuthority => 0x1001u32,
                Usage::PlatformEndorsementKey => 0x1002u32,
                Usage::PlatformDiffieHellman => 0x1003u32,
                Usage::ChipEndorsementKey => 0x1004u32,
                Usage::AmdRootKey => 0x0000u32,
                Usage::AmdSevKey => 0x0013u32,
            }
        }.encode(writer, Endianness::Little)?;
        Ok(())
    }
}

impl Encoder<Params> for Option<Algorithm> {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Params) -> Result<(), Error> {
        match self {
            None => 0x0000u32,
            Some(ref u) => match u {
                Algorithm::RsaSha256 => 0x0001u32,
                Algorithm::EcdsaSha256 => 0x0002u32,
                Algorithm::EcdhSha256 => 0x0003u32,
                Algorithm::RsaSha384 => 0x0101u32,
                Algorithm::EcdsaSha384 => 0x0102u32,
                Algorithm::EcdhSha384 => 0x0103u32,
            }
        }.encode(writer, Endianness::Little)?;
        Ok(())
    }
}

impl Encoder<Params> for Signature1 {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Params) -> Result<(), Error> {
        if self.sig.len() != 512 {
            Err(Error::Invalid(format!("signature length: {}", self.sig.len())))?
        }

        Some(self.usage).encode(writer, params)?;
        Some(self.algo).encode(writer, params)?;
        writer.write_all(&self.sig)?;
        Ok(())
    }
}

impl Encoder<Params> for Option<Signature1> {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Params) -> Result<(), Error> {
        match self {
            None => {
                (None as Option<Usage>).encode(writer, params)?;
                (None as Option<Algorithm>).encode(writer, params)?;
                writer.write_all(&[0u8; 512])?;
            },

            Some(ref s) => s.encode(writer, params)?,
        };

        Ok(())
    }
}

impl Encoder<Params> for Version1 {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Params) -> Result<(), Error> {
        self.0.encode(writer, Endianness::Little)?;
        self.1.encode(writer, Endianness::Little)?;
        Ok(())
    }
}

impl Encoder<Params> for PublicKey1 {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Params) -> Result<(), Error> {
        Some(self.usage).encode(writer, params)?;
        Some(self.algo).encode(writer, params)?;
        writer.write_all(&self.key)?;
        Ok(())
    }
}

impl Encoder<Params> for Body1 {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Params) -> Result<(), Error> {
        self.version.encode(writer, params)?;
        0u8.encode(writer, Endianness::Little)?;
        0u8.encode(writer, Endianness::Little)?;
        self.pubkey.encode(writer, params)?;
        self.sig1.encode(writer, params)?;
        self.sig2.encode(writer, params)
    }
}

impl Encoder<Params> for Versioned {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Params) -> Result<(), Error> {
        match self {
            Versioned::Version1(ref c) => {
                1u32.encode(writer, Endianness::Little)?;
                c.encode(writer, params)
            }
        }
    }
}

impl Encoder<Params> for Certificate {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Params) -> Result<(), Error> {
        self.0.encode(writer, params)
    }
}
