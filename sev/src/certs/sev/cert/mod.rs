// SPDX-License-Identifier: Apache-2.0

mod v1;

use super::*;

#[repr(C)]
#[derive(Copy, Clone)]
pub union Certificate {
    version: u32,
    v1: v1::Certificate,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.version() {
            1 => write!(f, "{:?}", unsafe { self.v1 }),
            v => write!(f, "Certificate {{ version: {} }}", v),
        }
    }
}

#[cfg(feature = "openssl")]
impl std::fmt::Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use codicon::Encoder;
        use std::fmt::Error;

        let key = PublicKey::try_from(self).or(Err(Error))?;

        let mut hsh = hash::Hasher::new(key.hash)?;

        self.encode(&mut hsh, Body).or(Err(Error))?;

        write!(f, "{} {} ", crate::certs::Usage::from(key.usage), key)?;
        for b in hsh.finish()?.iter() {
            write!(f, "{:02x}", *b)?;
        }

        Ok(())
    }
}

impl Eq for Certificate {}
impl PartialEq for Certificate {
    fn eq(&self, other: &Certificate) -> bool {
        if unsafe { self.version != other.version } {
            return false;
        }
        match self.version() {
            1 => unsafe { self.v1 == other.v1 },
            _ => false,
        }
    }
}

impl<U: Copy + Into<crate::certs::Usage>> PartialEq<U> for Certificate {
    fn eq(&self, other: &U) -> bool {
        if let Ok(a) = Usage::try_from(self) {
            return a == (*other).into();
        }

        false
    }
}

impl codicon::Decoder for Certificate {
    type Error = Error;

    fn decode(reader: &mut impl Read, params: ()) -> Result<Self> {
        Ok(match u32::from_le(reader.load()?) {
            1 => Certificate {
                v1: v1::Certificate::decode(reader, params)?,
            },
            _ => return Err(ErrorKind::InvalidData.into()),
        })
    }
}

impl codicon::Encoder for Certificate {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<()> {
        match self.version() {
            1 => unsafe { writer.save(&self.v1) },
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

#[cfg(feature = "openssl")]
impl codicon::Encoder<Body> for Certificate {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: Body) -> Result<()> {
        match self.version() {
            1 => unsafe { writer.save(&self.v1.body) },
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Certificate> for [Option<Signature>; 2] {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        match value.version() {
            1 => Ok([
                unsafe { &value.v1.sigs[0] }.try_into()?,
                unsafe { &value.v1.sigs[1] }.try_into()?,
            ]),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl TryFrom<&Certificate> for Usage {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        match value.version() {
            1 => Ok(unsafe { value.v1.body.data.key.usage }),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl TryFrom<&Certificate> for crate::certs::Usage {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        Ok(Usage::try_from(value)?.into())
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Certificate> for PublicKey<Usage> {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        match value.version() {
            1 => PublicKey::try_from(unsafe { &value.v1.body.data.key }),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key = PublicKey::try_from(self.0)?;

        let sigs: [Option<Signature>; 2] = self.1.try_into()?;
        for sig in sigs.iter() {
            if let Some(sig) = sig {
                if key.verify(self.1, &sig).is_ok() {
                    return Ok(());
                }
            }
        }

        Err(ErrorKind::InvalidInput.into())
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for (&ca::Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key: PublicKey<ca::Usage> = self.0.try_into()?;

        let sigs: [Option<Signature>; 2] = self.1.try_into()?;
        for sig in sigs.iter() {
            if let Some(sig) = sig {
                if key.verify(self.1, &sig).is_ok() {
                    return Ok(());
                }
            }
        }

        Err(ErrorKind::InvalidInput.into())
    }
}

#[cfg(feature = "openssl")]
impl Signer<Certificate> for PrivateKey<Usage> {
    type Output = ();

    fn sign(&self, target: &mut Certificate) -> Result<()> {
        match target.version() {
            1 => self.sign(unsafe { &mut target.v1 }),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl Certificate {
    #[cfg(feature = "openssl")]
    pub fn generate(usage: Usage) -> Result<(Self, PrivateKey<Usage>)> {
        let (crt, prv) = v1::Certificate::generate(usage)?;
        Ok((Certificate { v1: crt }, prv))
    }

    #[inline]
    fn version(&self) -> u32 {
        u32::from_le(unsafe { self.version })
    }
}
