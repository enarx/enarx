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

mod algo;
pub mod body;
pub mod sig;

use super::*;

use algo::Algorithm;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub body: body::Body,
    pub sigs: [sig::Signature; 2],
}

#[cfg(feature = "openssl")]
impl Certificate {
    pub fn generate(usage: Usage) -> Result<(Self, PrivateKey<Usage>)> {
        let (body, prv) = body::Body::generate(usage)?;
        Ok((
            Self {
                body,
                sigs: [sig::Signature::default(), sig::Signature::default()],
            },
            prv,
        ))
    }
}

impl codicon::Decoder for Certificate {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: ()) -> Result<Self> {
        Ok(Self {
            body: body::Body {
                ver: 1u32.to_le(),
                data: reader.load()?,
            },
            sigs: [reader.load()?, reader.load()?],
        })
    }
}

#[cfg(feature = "openssl")]
impl Signer<Certificate> for PrivateKey<Usage> {
    type Output = ();

    fn sign(&self, target: &mut Certificate) -> Result<()> {
        let slot = if target.sigs[0].is_empty() {
            &mut target.sigs[0]
        } else if target.sigs[1].is_empty() {
            &mut target.sigs[1]
        } else {
            return Err(ErrorKind::InvalidInput.into());
        };

        let mut sig = sign::Signer::new(self.hash, &self.key)?;
        if self.key.id() == pkey::Id::RSA {
            sig.set_rsa_padding(rsa::Padding::PKCS1_PSS)?;
            sig.set_rsa_pss_saltlen(sign::RsaPssSaltlen::DIGEST_LENGTH)?;
        }

        sig.save(&target.body)?;

        let sig = crate::certs::Signature {
            usage: self.usage.into(),
            hash: self.hash,
            kind: self.key.id(),
            sig: sig.sign_to_vec()?,
            id: self.id,
        };

        *slot = sig::Signature::try_from(sig)?;
        Ok(())
    }
}
