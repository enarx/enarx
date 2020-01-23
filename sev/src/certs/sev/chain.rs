// SPDX-License-Identifier: Apache-2.0

use super::*;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct Chain {
    pub pdh: Certificate,
    pub pek: Certificate,
    pub oca: Certificate,
    pub cek: Certificate,
}

impl codicon::Decoder for Chain {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: ()) -> Result<Self> {
        let pdh = Certificate::decode(reader, ())?;
        if Usage::try_from(&pdh)? != Usage::PDH {
            return Err(ErrorKind::InvalidInput.into());
        }

        let pek = Certificate::decode(reader, ())?;
        if Usage::try_from(&pek)? != Usage::PEK {
            return Err(ErrorKind::InvalidInput.into());
        }

        let oca = Certificate::decode(reader, ())?;
        if Usage::try_from(&oca)? != Usage::OCA {
            return Err(ErrorKind::InvalidInput.into());
        }

        let cek = Certificate::decode(reader, ())?;
        if Usage::try_from(&cek)? != Usage::CEK {
            return Err(ErrorKind::InvalidInput.into());
        }

        Ok(Self { pdh, pek, oca, cek })
    }
}

impl codicon::Encoder for Chain {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<()> {
        self.pdh.encode(writer, ())?;
        self.pek.encode(writer, ())?;
        self.oca.encode(writer, ())?;
        self.cek.encode(writer, ())
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for Chain {
    type Output = Certificate;

    fn verify(self) -> Result<Certificate> {
        (&self.oca, &self.oca).verify()?;
        (&self.oca, &self.pek).verify()?;
        (&self.cek, &self.pek).verify()?;
        (&self.pek, &self.pdh).verify()?;
        Ok(self.pdh)
    }
}
