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

mod cert;
mod chain;

pub use cert::Certificate;
pub use chain::Chain;

use super::*;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Usage(u32);

impl Usage {
    pub const OCA: Usage = Usage(super::Usage::OCA.0);
    pub const CEK: Usage = Usage(super::Usage::CEK.0);
    pub const PEK: Usage = Usage(super::Usage::PEK.0);
    pub const PDH: Usage = Usage(super::Usage::PDH.0);
}

impl TryFrom<super::Usage> for Usage {
    type Error = ();

    fn try_from(value: super::Usage) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            super::Usage::OCA => Usage::OCA,
            super::Usage::CEK => Usage::CEK,
            super::Usage::PEK => Usage::PEK,
            super::Usage::PDH => Usage::PDH,
            _ => return Err(()),
        })
    }
}

impl From<Usage> for super::Usage {
    fn from(value: Usage) -> Self {
        Self(value.0)
    }
}

impl PartialEq<super::Usage> for Usage {
    fn eq(&self, other: &super::Usage) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<Usage> for super::Usage {
    fn eq(&self, other: &Usage) -> bool {
        self.0 == other.0
    }
}
