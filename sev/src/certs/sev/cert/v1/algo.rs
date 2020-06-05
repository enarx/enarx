// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use super::*;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Algorithm(u32);

#[allow(dead_code)]
impl Algorithm {
    pub const RSA_SHA256: Algorithm = Algorithm(0x0001u32.to_le());
    pub const ECDSA_SHA256: Algorithm = Algorithm(0x0002u32.to_le());
    pub const ECDH_SHA256: Algorithm = Algorithm(0x0003u32.to_le());
    pub const RSA_SHA384: Algorithm = Algorithm(0x0101u32.to_le());
    pub const ECDSA_SHA384: Algorithm = Algorithm(0x0102u32.to_le());
    pub const ECDH_SHA384: Algorithm = Algorithm(0x0103u32.to_le());
    pub const NONE: Algorithm = Algorithm(0x0000u32.to_le());
}

impl Default for Algorithm {
    fn default() -> Algorithm {
        Algorithm::NONE
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<Algorithm> for pkey::Id {
    type Error = Error;

    fn try_from(value: Algorithm) -> Result<Self> {
        Ok(match value {
            Algorithm::RSA_SHA256 | Algorithm::RSA_SHA384 => pkey::Id::RSA,
            Algorithm::ECDSA_SHA256 | Algorithm::ECDSA_SHA384 => pkey::Id::EC,
            Algorithm::ECDH_SHA256 | Algorithm::ECDH_SHA384 => pkey::Id::EC,
            _ => return Err(ErrorKind::InvalidInput.into()),
        })
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<Algorithm> for hash::MessageDigest {
    type Error = Error;

    fn try_from(value: Algorithm) -> Result<Self> {
        match value {
            Algorithm::RSA_SHA256 | Algorithm::ECDSA_SHA256 | Algorithm::ECDH_SHA256 => {
                Ok(hash::MessageDigest::sha256())
            }

            Algorithm::RSA_SHA384 | Algorithm::ECDSA_SHA384 | Algorithm::ECDH_SHA384 => {
                Ok(hash::MessageDigest::sha384())
            }

            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}
