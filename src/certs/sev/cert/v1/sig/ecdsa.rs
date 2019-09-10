// Copyright 2019 Red Hat
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(feature = "openssl")]
use {super::*, openssl::ecdsa};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Signature {
    r: [u8; 72],
    s: [u8; 72],
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Signature {{ r: {:?}, s: {:?} }}",
            self.r.iter(),
            self.s.iter()
        )
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.r[..] == other.r[..] && self.s[..] == other.s[..]
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            r: [0u8; 72],
            s: [0u8; 72],
        }
    }
}

#[cfg(feature = "openssl")]
impl From<ecdsa::EcdsaSig> for Signature {
    #[inline]
    fn from(value: ecdsa::EcdsaSig) -> Self {
        Signature {
            r: value.r().into_le(),
            s: value.s().into_le(),
        }
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::from_der(value)?.into())
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Signature> for ecdsa::EcdsaSig {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        let r = bn::BigNum::from_le(&value.r)?;
        let s = bn::BigNum::from_le(&value.s)?;
        Ok(ecdsa::EcdsaSig::from_private_components(r, s)?)
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Signature> for Vec<u8> {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::try_from(value)?.to_der()?)
    }
}
