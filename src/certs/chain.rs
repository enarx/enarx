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

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct Chain {
    pub ca: ca::Chain,
    pub sev: sev::Chain,
}

impl codicon::Decoder for Chain {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: ()) -> Result<Self> {
        let sev = sev::Chain::decode(reader, ())?;
        let ca = ca::Chain::decode(reader, ())?;
        Ok(Self { ca, sev })
    }
}

impl codicon::Encoder for Chain {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<()> {
        self.sev.encode(writer, ())?;
        self.ca.encode(writer, ())
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for Chain {
    type Output = sev::Certificate;

    fn verify(self) -> Result<sev::Certificate> {
        let ask = self.ca.verify()?;
        (&ask, &self.sev.cek).verify()?;
        self.sev.verify()
    }
}
