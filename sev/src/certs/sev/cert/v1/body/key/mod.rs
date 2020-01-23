// SPDX-License-Identifier: Apache-2.0

pub mod ecc;
pub mod rsa;

use super::*;

#[repr(C)]
#[derive(Copy, Clone)]
union PubKeys {
    ecc: ecc::PubKey,
    rsa: rsa::PubKey,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PubKey {
    pub usage: Usage,
    pub algo: Algorithm,
    key: PubKeys,
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.algo {
            Algorithm::RSA_SHA256 | Algorithm::RSA_SHA384 => write!(
                f,
                "PubKey {{ usage: {:?}, algo: {:?}, key: {:?} }}",
                self.usage,
                self.algo,
                unsafe { self.key.rsa }
            ),

            _ => write!(
                f,
                "PubKey {{ usage: {:?}, algo: {:?}, key: {:?} }}",
                self.usage,
                self.algo,
                unsafe { self.key.ecc }
            ),
        }
    }
}

impl Eq for PubKey {}
impl PartialEq for PubKey {
    fn eq(&self, other: &PubKey) -> bool {
        self.usage == other.usage
            && self.algo == other.algo
            && match self.algo {
                Algorithm::RSA_SHA256 | Algorithm::RSA_SHA384 => unsafe {
                    self.key.rsa == other.key.rsa
                },
                _ => unsafe { self.key.ecc == other.key.ecc },
            }
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&PubKey> for pkey::PKey<pkey::Public> {
    type Error = Error;

    fn try_from(v: &PubKey) -> Result<Self> {
        match v.algo.try_into()? {
            pkey::Id::RSA => Ok(unsafe { &v.key.rsa }.try_into()?),
            pkey::Id::EC => Ok(unsafe { &v.key.ecc }.try_into()?),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&PubKey> for PublicKey<Usage> {
    type Error = Error;

    fn try_from(value: &PubKey) -> Result<Self> {
        let hash = value.algo.try_into()?;
        let key = value.try_into()?;
        Ok(Self {
            hash,
            key,
            id: None,
            usage: value.usage,
        })
    }
}

#[cfg(feature = "openssl")]
impl PubKey {
    pub fn generate(usage: Usage) -> Result<(PubKey, PrivateKey<Usage>)> {
        let algo = match usage {
            Usage::OCA => Algorithm::ECDSA_SHA256,
            Usage::PEK => Algorithm::ECDSA_SHA256,
            Usage::CEK => Algorithm::ECDSA_SHA256,
            Usage::PDH => Algorithm::ECDH_SHA256,
            _ => return Err(ErrorKind::InvalidInput.into()),
        };

        let (key, prv) = ecc::PubKey::generate(ecc::group::Group::P384)?;
        let prv = pkey::PKey::from_ec_key(prv)?;

        Ok((
            Self {
                usage,
                algo,
                key: PubKeys { ecc: key },
            },
            PrivateKey {
                usage,
                key: prv,
                id: None,
                hash: algo.try_into()?,
            },
        ))
    }
}
