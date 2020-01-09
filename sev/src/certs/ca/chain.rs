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
    pub ask: Certificate,
    pub ark: Certificate,
}

impl codicon::Decoder for Chain {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: ()) -> Result<Self> {
        let ask = Certificate::decode(reader, ())?;
        if Usage::try_from(&ask)? != Usage::ASK {
            return Err(ErrorKind::InvalidInput.into());
        }

        let ark = Certificate::decode(reader, ())?;
        if Usage::try_from(&ark)? != Usage::ARK {
            return Err(ErrorKind::InvalidInput.into());
        }

        Ok(Self { ask, ark })
    }
}

impl codicon::Encoder for Chain {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<()> {
        self.ask.encode(writer, ())?;
        self.ark.encode(writer, ())
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for Chain {
    type Output = Certificate;

    fn verify(self) -> Result<Certificate> {
        (&self.ark, &self.ark).verify()?;
        (&self.ark, &self.ask).verify()?;
        Ok(self.ask)
    }
}
