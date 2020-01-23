// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use super::*;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Signature([u8; 512]);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Signature({:?})", self.0.iter())
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0u8; 512])
    }
}

#[cfg(feature = "openssl")]
impl From<bn::BigNum> for Signature {
    #[inline]
    fn from(value: bn::BigNum) -> Self {
        Signature(value.into_le())
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self> {
        Ok(bn::BigNum::from_slice(value)?.into())
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Signature> for bn::BigNum {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        Ok(bn::BigNum::from_le(&value.0)?)
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Signature> for Vec<u8> {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        Ok(bn::BigNum::try_from(value)?.to_vec())
    }
}
