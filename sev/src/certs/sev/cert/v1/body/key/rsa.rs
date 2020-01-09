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

use super::*;

#[cfg(feature = "openssl")]
use openssl::rsa;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PubKey {
    modulus_size: u32,
    pubexp: [u8; 512],
    modulus: [u8; 512],
}

impl PubKey {
    fn bytes(&self) -> Result<usize> {
        match u32::from_le(self.modulus_size) {
            2048 => Ok(256),
            4096 => Ok(512),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let size = self.bytes().or(Err(std::fmt::Error))?;
        let pdata = &self.pubexp[..size];
        let mdata = &self.modulus[..size];
        write!(
            f,
            "PubKey {{ modulus_size: {:?}, pubexp: {:?}, modulus: {:?} }}",
            self.modulus_size, pdata, mdata
        )
    }
}

impl Eq for PubKey {}
impl PartialEq for PubKey {
    fn eq(&self, other: &PubKey) -> bool {
        self.modulus_size == other.modulus_size
            && self.pubexp[..] == other.pubexp[..]
            && self.modulus[..] == other.modulus[..]
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&PubKey> for rsa::Rsa<pkey::Public> {
    type Error = Error;

    fn try_from(value: &PubKey) -> Result<Self> {
        let s = value.bytes()?;
        Ok(rsa::Rsa::from_public_components(
            bn::BigNum::from_le(&value.modulus[..s])?,
            bn::BigNum::from_le(&value.pubexp[..s])?,
        )?)
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&PubKey> for pkey::PKey<pkey::Public> {
    type Error = Error;

    fn try_from(value: &PubKey) -> Result<Self> {
        Ok(pkey::PKey::from_rsa(value.try_into()?)?)
    }
}

#[cfg(feature = "openssl")]
impl PubKey {
    pub fn generate(bits: u32) -> Result<(Self, rsa::Rsa<pkey::Private>)> {
        let prv = rsa::Rsa::generate(bits)?;
        let n = prv.n().into_le();
        let e = prv.e().into_le();
        Ok((
            Self {
                modulus_size: bits.to_le(),
                pubexp: e,
                modulus: n,
            },
            prv,
        ))
    }
}
