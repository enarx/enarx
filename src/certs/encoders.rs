#![allow(clippy::unit_arg)]

use endicon::Endianness;
use codicon::Encoder;
use openssl::*;

use std::num::NonZeroU128;
use std::io::{Error, ErrorKind, Result, Write};

use super::common::*;
use super::*;

#[derive(Copy, Clone, Debug)]
struct Sev(bool);

#[derive(Copy, Clone, Debug)]
struct Ca(bool);

impl Encoder<Sev> for Firmware {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: Sev) -> Result<()> {
        self.0.encode(writer, Endianness::Little)?;
        self.1.encode(writer, Endianness::Little)
    }
}

impl Encoder<Sev> for Option<Usage> {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: Sev) -> Result<()> {
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
        }.encode(writer, Endianness::Little)
    }
}

impl Encoder<Internal<usize>> for bn::BigNumRef {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, params: Internal<usize>) -> Result<()> {
        let buf = self.to_vec();
        if buf.len() > params.0 {
            return Err(ErrorKind::InvalidInput.into());
        }

        for b in buf.iter().rev().cloned() {
            writer.write_all(&[b])?;
        }

        for _ in buf.len() .. params.0 {
            writer.write_all(&[0u8])?;
        }

        Ok(())
    }
}

impl Encoder<Sev> for rsa::Rsa<pkey::Public> {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: Sev) -> Result<()> {
        let msize: u32 = self.size() * 8;
        msize.encode(writer, Endianness::Little)?;
        self.e().encode(writer, Internal(512))?;
        self.n().encode(writer, Internal(512))
    }
}

// We can't currently get the Nid out of the EcGroup. See this
// pull request for more information:
//   https://github.com/sfackler/rust-openssl/pull/1084
//
// For now, we will work around this by guessing the curve from the
// degree of the curve.
impl Encoder<Sev> for ec::EcKey<pkey::Public> {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: Sev) -> Result<()> {
        let mut ctx = bn::BigNumContext::new()?;
        let mut x = bn::BigNum::new()?;
        let mut y = bn::BigNum::new()?;
        let g = self.group();

        self.public_key().affine_coordinates_gfp(g, &mut x, &mut y, &mut ctx)?;

        match g.degree() {
            256 => 1u32.encode(writer, Endianness::Little)?,
            384 => 2u32.encode(writer, Endianness::Little)?,
            _ => return Err(ErrorKind::InvalidInput.into()),
        }

        x.encode(writer, Internal(72))?;
        y.encode(writer, Internal(72))?;
        writer.write_all(&[0u8; 880]) // Reserved
    }
}

impl Encoder<Kind> for Option<IdHash> {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, kind: Kind) -> Result<()> {
        match self {
            None => 0x0000u32,
            Some(ih) => match (kind, ih.0, ih.1.size() * 8) {
                (Kind::Signing,  pkey::Id::RSA, 256) => 0x0001u32,
                (Kind::Signing,  pkey::Id::RSA, 384) => 0x0101u32,
                (Kind::Signing,  pkey::Id::EC,  256) => 0x0002u32,
                (Kind::Signing,  pkey::Id::EC,  384) => 0x0102u32,
                (Kind::Exchange, pkey::Id::EC,  256) => 0x0003u32,
                (Kind::Exchange, pkey::Id::EC,  384) => 0x0103u32,
                _ => return Err(ErrorKind::InvalidInput.into()),
            },
        }.encode(writer, Endianness::Little)
    }
}

impl Encoder<Sev> for PublicKey {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, params: Sev) -> Result<()> {
        Some(self.usage).encode(writer, params)?;
        Some(IdHash(self.key.id(), self.hash)).encode(writer, self.usage.into())?;

        match self.key.id() {
            pkey::Id::RSA => self.key.rsa()?.encode(writer, params),
            pkey::Id::EC => self.key.ec_key()?.encode(writer, params),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl Encoder<Sev> for ecdsa::EcdsaSig {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: Sev) -> Result<()> {
        self.r().encode(writer, Internal(72))?;
        self.s().encode(writer, Internal(72))?;
        writer.write_all(&[0u8; 368]) // Reserved
    }
}

impl Encoder<Sev> for Option<Signature> {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, params: Sev) -> Result<()> {
        match self {
            Some(sig) => {
                Some(sig.usage).encode(writer, params)?;
                Some(IdHash(sig.key, sig.hash)).encode(writer, sig.usage.into())?;

                match sig.key {
                    pkey::Id::RSA => bn::BigNum::from_slice(&sig.sig)?
                        .encode(writer, Internal(512)),

                    pkey::Id::EC => ecdsa::EcdsaSig::from_der(&sig.sig)?
                        .encode(writer, params),

                    _ => Err(ErrorKind::InvalidInput.into()),
                }
            },

            None => {
                Option::<Usage>::None.encode(writer, params)?;
                Option::<IdHash>::None.encode(writer, Kind::Signing)?;
                writer.write_all(&[0u8; 512])
            },
        }
    }
}

impl Encoder<Sev> for Certificate {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, params: Sev) -> Result<()> {
        self.version.encode(writer, Endianness::Little)?;

        self.firmware.unwrap().encode(writer, params)?;

        0u16.encode(writer, Endianness::Little)?; // Reserved

        self.key.encode(writer, params)?;

        if params.0 {
            self.sig[0].encode(writer, params)?;
            self.sig[1].encode(writer, params)?;
        }

        Ok(())
    }
}

impl Encoder<Ca> for Option<NonZeroU128> {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: Ca) -> Result<()> {
        match self {
            Some(i) => i.get(),
            None => 0,
        }.encode(writer, Endianness::Little)
    }
}

impl Encoder<Ca> for Usage {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: Ca) -> Result<()> {
        match self {
            Usage::AmdRootKey => 0x0000u32,
            Usage::AmdSevKey => 0x0013u32,
            _ => return Err(ErrorKind::InvalidInput.into()),
        }.encode(writer, Endianness::Little)
    }
}

impl Encoder<Ca> for rsa::Rsa<pkey::Public> {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: Ca) -> Result<()> {
        let size: u32 = self.size() * 8;
        size.encode(writer, Endianness::Little)?; // PUBEXP_SIZE
        size.encode(writer, Endianness::Little)?; // MODULUS_SIZE
        self.e().encode(writer, Internal(self.size() as usize))?;
        self.n().encode(writer, Internal(self.size() as usize))
    }
}

impl Encoder<Ca> for Certificate {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, params: Ca) -> Result<()> {
        let sig = match self.sig.first() {
            Some(Some(ref s)) => s,
            _ => return Err(ErrorKind::InvalidInput.into()),
        };

        self.version.encode(writer, Endianness::Little)?;
        self.key.id.encode(writer, params)?;
        sig.id.encode(writer, params)?;
        self.key.usage.encode(writer, params)?;
        0u128.encode(writer, Endianness::Little)?;

        let rsa = self.key.key.rsa()?;
        rsa.encode(writer, params)?;

        if params.0 {
            let s = bn::BigNum::from_slice(&sig.sig)?;
            s.encode(writer, Internal(rsa.size() as usize))?;
        }

        Ok(())
    }
}

impl Certificate {
    pub fn save(&self, writer: &mut impl Write) -> Result<()> {
        match self.firmware {
            Some(_) => self.encode(writer, Sev(true)),
            None => self.encode(writer, Ca(true)),
        }
    }
}

impl PrivateKey {
    pub fn save(&self, writer: &mut impl Write) -> Result<()> {
        let buf = self.key.private_key_to_der()?;
        writer.write_all(&buf)?;
        Ok(())
    }

    pub fn sign(&self, crt: &mut Certificate) -> Result<()> {
        let kind: Kind = self.usage.into();
        if kind != Kind::Signing {
            return Err(ErrorKind::InvalidInput.into());
        }

        let mut sig = sign::Signer::new(self.hash, &self.key)?;

        if self.key.id() == pkey::Id::RSA {
            sig.set_rsa_padding(rsa::Padding::PKCS1_PSS)?;
            sig.set_rsa_pss_saltlen(sign::RsaPssSaltlen::DIGEST_LENGTH)?;
        }

        match crt.firmware {
            Some(_) => crt.encode(&mut sig, Sev(false))?,
            None => crt.encode(&mut sig, Ca(false))?,
        }

        let sig = Signature {
            usage: self.usage,
            hash: self.hash,
            sig: sig.sign_to_vec()?,
            key: self.key.id(),
            id: self.id,
        };

        if crt.sig[0].is_none() { crt.sig[0] = Some(sig); }
        else if crt.sig[1].is_none() { crt.sig[1] = Some(sig); }
        else { return Err(ErrorKind::InvalidInput.into()); }

        Ok(())
    }
}

impl PublicKey {
    pub fn verify(&self, crt: &Certificate, sig: &Signature) -> std::result::Result<(), ()> {
        let usage = self.usage == sig.usage;
        let hash = self.hash.size() == sig.hash.size();
        let id = sig.id.is_none() || sig.id == self.id;
        if !usage || !hash || !id { Err(())? }

        let mut ver = sign::Verifier::new(sig.hash, &self.key).or(Err(()))?;
        if self.key.id() == pkey::Id::RSA {
            ver.set_rsa_padding(rsa::Padding::PKCS1_PSS).or(Err(()))?;
            ver.set_rsa_pss_saltlen(sign::RsaPssSaltlen::DIGEST_LENGTH).or(Err(()))?;
        }

        match crt.firmware {
            Some(_) => crt.encode(&mut ver, Sev(false)).or(Err(()))?,
            None => crt.encode(&mut ver, Ca(false)).or(Err(()))?,
        }

        if ver.verify(&sig.sig).or(Err(()))? { Ok(()) } else { Err(()) }
    }
}

impl std::fmt::Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut hsh = hash::Hasher::new(self.key.hash)?;

        match self.firmware {
            Some(_) => self.encode(&mut hsh, Sev(false)).or(Err(std::fmt::Error))?,
            None => self.encode(&mut hsh, Ca(false)).or(Err(std::fmt::Error))?,
        }

        write!(f, "{} {} ", self.key.usage, self.key)?;
        for b in hsh.finish()?.iter() {
            write!(f, "{:02x}", *b)?;
        }

        Ok(())
    }
}
