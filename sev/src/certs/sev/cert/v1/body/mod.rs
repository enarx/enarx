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
