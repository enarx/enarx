// SPDX-License-Identifier: Apache-2.0

pub mod key;

use super::*;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Data {
    pub firmware: crate::Version,
    pub reserved: u16,
    pub key: key::PubKey,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub ver: u32,
    pub data: Data,
}

#[cfg(feature = "openssl")]
impl Body {
    pub fn generate(usage: Usage) -> Result<(Body, PrivateKey<Usage>)> {
        let (key, prv) = key::PubKey::generate(usage)?;
        Ok((
            Body {
                ver: 1u32.to_le(),
                data: Data {
                    firmware: Default::default(),
                    reserved: 0,
                    key,
                },
            },
            prv,
        ))
    }
}
