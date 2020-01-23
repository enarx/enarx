// SPDX-License-Identifier: Apache-2.0

mod ecdsa;
mod rsa;

use super::*;
use crate::certs::Usage;

#[repr(C)]
#[derive(Copy, Clone)]
union Signatures {
    ecdsa: ecdsa::Signature,
    rsa: rsa::Signature,
}

impl Default for Signatures {
    fn default() -> Self {
        Signatures {
            rsa: rsa::Signature::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Signature {
    usage: Usage,
    algo: Algorithm,
    sig: Signatures,
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            usage: Usage::INV,
            algo: Algorithm::NONE,
            sig: Signatures::default(),
        }
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.algo {
            Algorithm::RSA_SHA256 | Algorithm::RSA_SHA384 => write!(
                f,
                "Signature {{ usage: {:?}, algo: {:?}, sig: {:?} }}",
                self.usage,
                self.algo,
                unsafe { self.sig.rsa }
            ),

            _ => write!(
                f,
                "Signature {{ usage: {:?}, algo: {:?}, sig: {:?} }}",
                self.usage,
                self.algo,
                unsafe { self.sig.ecdsa }
            ),
        }
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.usage == other.usage
            && self.algo == other.algo
            && match self.algo {
                Algorithm::RSA_SHA256 | Algorithm::RSA_SHA384 => unsafe {
                    self.sig.rsa == other.sig.rsa
                },

                _ => unsafe { self.sig.ecdsa == other.sig.ecdsa },
            }
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<crate::certs::Signature> for Signature {
    type Error = Error;

    fn try_from(value: crate::certs::Signature) -> Result<Self> {
        if value.id.is_some() {
            return Err(ErrorKind::InvalidInput.into());
        }

        let (sig, algo) = match value.kind {
            pkey::Id::RSA => {
                let rsa = rsa::Signature::try_from(&value.sig[..])?;
                let sig = Signatures { rsa };
                match value.hash.type_() {
                    nid::Nid::SHA256 => (sig, Algorithm::RSA_SHA256),
                    nid::Nid::SHA384 => (sig, Algorithm::RSA_SHA384),
                    _ => return Err(ErrorKind::InvalidInput.into()),
                }
            }

            pkey::Id::EC => {
                let ecdsa = ecdsa::Signature::try_from(&value.sig[..])?;
                let sig = Signatures { ecdsa };
                match value.hash.type_() {
                    nid::Nid::SHA256 => (sig, Algorithm::ECDSA_SHA256),
                    nid::Nid::SHA384 => (sig, Algorithm::ECDSA_SHA384),
                    _ => return Err(ErrorKind::InvalidInput.into()),
                }
            }

            _ => return Err(ErrorKind::InvalidInput.into()),
        };

        Ok(Signature {
            usage: value.usage,
            algo,
            sig,
        })
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Signature> for Option<crate::certs::Signature> {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self> {
        if value.is_empty() {
            return Ok(None);
        }

        let usage = value.usage;
        let hash = value.algo.try_into()?;
        let kind = value.algo.try_into()?;
        let sig = match kind {
            pkey::Id::RSA => Vec::try_from(unsafe { &value.sig.rsa })?,
            pkey::Id::EC => Vec::try_from(unsafe { &value.sig.ecdsa })?,
            _ => return Err(ErrorKind::InvalidInput.into()),
        };

        Ok(Some(crate::certs::Signature {
            hash,
            kind,
            sig,
            usage,
            id: None,
        }))
    }
}

impl Signature {
    #[cfg(feature = "openssl")]
    pub fn is_empty(&self) -> bool {
        match self.usage {
            Usage::OCA | Usage::CEK | Usage::PEK | Usage::PDH | Usage::ARK | Usage::ASK => {
                match self.algo {
                    Algorithm::RSA_SHA256
                    | Algorithm::RSA_SHA384
                    | Algorithm::ECDSA_SHA256
                    | Algorithm::ECDSA_SHA384 => false,
                    _ => true,
                }
            }
            _ => true,
        }
    }
}
