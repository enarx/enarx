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
use super::*;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Group(u32);

#[cfg(feature = "openssl")]
impl Group {
    pub const P256: Group = Group(1u32.to_le());
    pub const P384: Group = Group(2u32.to_le());

    pub fn size(self) -> Result<usize> {
        Ok(match self {
            Group::P256 => 32,
            Group::P384 => 48,
            _ => return Err(ErrorKind::InvalidInput.into())
        })
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<Group> for nid::Nid {
    type Error = Error;

    fn try_from(value: Group) -> Result<Self> {
        Ok(match value {
            Group::P256 => nid::Nid::X9_62_PRIME256V1,
            Group::P384 => nid::Nid::SECP384R1,
            _ => return Err(ErrorKind::InvalidInput.into())
        })
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<nid::Nid> for Group {
    type Error = Error;

    fn try_from(value: nid::Nid) -> Result<Self> {
        Ok(match value {
            nid::Nid::X9_62_PRIME256V1 => Group::P256,
            nid::Nid::SECP384R1 => Group::P384,
            _ => return Err(ErrorKind::InvalidInput.into())
        })
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<Group> for ec::EcGroup {
    type Error = Error;

    fn try_from(value: Group) -> Result<Self> {
        Ok(ec::EcGroup::from_curve_name(value.try_into()?)?)
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&ec::EcGroupRef> for Group {
    type Error = Error;

    fn try_from(value: &ec::EcGroupRef) -> Result<Self> {
        value.curve_name().ok_or(ErrorKind::InvalidInput)?.try_into()
    }
}
