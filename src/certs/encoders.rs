#![allow(clippy::unit_arg)]

use endicon::Endianness;
use codicon::Encoder;
use std::io::Write;

use std::num::NonZeroU128;

use super::*;

#[derive(Copy, Clone, Debug)]
struct Sev1(bool);

#[derive(Copy, Clone, Debug)]
struct Ca1(bool);

fn field(writer: &mut impl Write, data: &[u8], field: usize) -> Result<(), Error> {
    writer.write_all(data)?;
    for _ in data.len() .. field {
        writer.write_all(&[0u8; 1])?;
    }
    Ok(())
}

impl Encoder<usize> for RsaKey {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, fill: usize) -> Result<(), Error> {
        let msize = match self.modulus.len() * 8 {
            2048 => 2048u32,
            4096 => 4096u32,
            s => Err(Error::Invalid(format!("modulus size: {}", s)))?,
        };

        msize.encode(writer, Endianness::Little)?;
        field(writer, &self.pubexp, fill)?;
        field(writer, &self.modulus, fill)
    }
}

impl Encoder<Sev1> for Option<Usage> {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Sev1) -> Result<(), Error> {
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

impl Encoder<Sev1> for Option<SigAlgo> {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Sev1) -> Result<(), Error> {
        match self {
            None => 0x0000u32,
            Some(ref u) => match u {
                SigAlgo::RsaSha256 => 0x0001u32,
                SigAlgo::EcdsaSha256 => 0x0002u32,
                SigAlgo::RsaSha384 => 0x0101u32,
                SigAlgo::EcdsaSha384 => 0x0102u32,
            }
        }.encode(writer, Endianness::Little)?;
        Ok(())
    }
}

impl Encoder<Sev1> for Option<ExcAlgo> {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Sev1) -> Result<(), Error> {
        match self {
            None => 0x0000u32,
            Some(ref u) => match u {
                ExcAlgo::EcdhSha256 => 0x0003u32,
                ExcAlgo::EcdhSha384 => 0x0103u32,
            }
        }.encode(writer, Endianness::Little)?;
        Ok(())
    }
}

impl Encoder<Sev1> for Option<Algo> {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Sev1) -> Result<(), Error> {
        Ok(match self {
            None => 0x0000u32.encode(writer, Endianness::Little)?,
            Some(a) => match a {
                Algo::Sig(s) => Some(*s).encode(writer, params)?,
                Algo::Exc(e) => Some(*e).encode(writer, params)?,
            }
        })
    }
}

impl Encoder<Sev1> for Firmware {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Sev1) -> Result<(), Error> {
        self.0.encode(writer, Endianness::Little)?;
        self.1.encode(writer, Endianness::Little)?;
        Ok(())
    }
}

impl Encoder<Sev1> for RsaKey {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Sev1) -> Result<(), Error> {
        self.encode(writer, 4096 / 8)
    }
}

impl Encoder<Sev1> for Curve {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Sev1) -> Result<(), Error> {
        Ok(match self {
            Curve::P256 => 1u32,
            Curve::P384 => 2u32,
        }.encode(writer, Endianness::Little)?)
    }
}

impl Encoder<Sev1> for EccKey {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Sev1) -> Result<(), Error> {
        self.curve.encode(writer, params)?;
        field(writer, &self.x, 576 / 8)?;
        field(writer, &self.y, 576 / 8)?;
        writer.write_all(&[0u8; 880])?; // Reserved
        Ok(())
    }
}

impl Encoder<Sev1> for Key {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Sev1) -> Result<(), Error> {
        match self {
            Key::Rsa(rsa) => rsa.encode(writer, params),
            Key::Ecc(ecc) => ecc.encode(writer, params),
        }
    }
}

impl Encoder<Sev1> for PublicKey {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Sev1) -> Result<(), Error> {
        Some(self.usage).encode(writer, params)?;
        Some(self.algo).encode(writer, params)?;
        self.key.encode(writer, params)
    }
}

impl Encoder<Sev1> for Option<&Signature> {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Sev1) -> Result<(), Error> {
        match self {
            None => {
                (None as Option<Usage>).encode(writer, params)?;
                (None as Option<SigAlgo>).encode(writer, params)?;
                writer.write_all(&[0u8; 512])?;
            },

            Some(ref s) => {
                if s.sig.len() != 512 {
                    Err(Error::Invalid(format!("signature length: {}", s.sig.len())))?
                }

                Some(s.usage).encode(writer, params)?;
                Some(s.algo).encode(writer, params)?;
                writer.write_all(&s.sig)?;
            },
        };

        Ok(())
    }
}

impl Encoder<Sev1> for Certificate {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Sev1) -> Result<(), Error> {
        self.version.encode(writer, Endianness::Little)?;
        self.firmware.unwrap().encode(writer, params)?;
        0u8.encode(writer, Endianness::Little)?;
        0u8.encode(writer, Endianness::Little)?;
        self.key.encode(writer, params)?;

        if params.0 {
            self.sigs.get(0).encode(writer, params)?;
            self.sigs.get(1).encode(writer, params)?;
        }

        Ok(())
    }
}

impl Encoder<Ca1> for RsaKey {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Ca1) -> Result<(), Error> {
        let psize = match self.pubexp.len() {
            256 => 2048u32,
            512 => 4096u32,
            s => Err(Error::Invalid(format!("pubexp size: {}", s)))?,
        };

        psize.encode(writer, Endianness::Little)?;

        self.encode(writer, 0)
    }
}

impl Encoder<Ca1> for Option<NonZeroU128> {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: Ca1) -> Result<(), Error> {
        Ok(match self {
            None => 0,
            Some(nz) => nz.get(),
        }.encode(writer, Endianness::Little)?)
    }
}

impl Encoder<Ca1> for Certificate {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, params: Ca1) -> Result<(), Error> {
        self.version.encode(writer, Endianness::Little)?;
        self.key.id.encode(writer, params)?;
        self.sigs[0].id.encode(writer, params)?;
        Some(self.key.usage).encode(writer, Sev1(params.0))?;
        0u128.encode(writer, Endianness::Little)?;

        match self.key.key {
            Key::Rsa(ref rsa) => rsa.encode(writer, params)?,
            _ => Err(Error::Invalid(format!("key: {:?}", self.key.key)))?,
        }

        if params.0 {
            writer.write_all(&self.sigs[0].sig)?;
        }

        Ok(())
    }
}

impl Encoder for Certificate {
    type Error = Error;
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), Error> {
        Ok(match self.firmware {
            Some(_) => match self.version {
                1 => self.encode(writer, Sev1(true))?,
                v => Err(Error::Invalid(format!("version: {}", v)))?,
            },

            None => match self.version {
                1 => self.encode(writer, Ca1(true))?,
                v => Err(Error::Invalid(format!("version: {}", v)))?,
            },
        })
    }
}

impl Certificate {
    pub(crate) fn body(&self) -> Result<Vec<u8>, Error> {
        Ok(match self.firmware {
            Some(_) => match self.version {
                1 => self.encode_buf(Sev1(false))?,
                v => Err(Error::Invalid(format!("version: {}", v)))?,
            },

            None => match self.version {
                1 => self.encode_buf(Ca1(false))?,
                v => Err(Error::Invalid(format!("version: {}", v)))?,
            },
        })
    }
}
