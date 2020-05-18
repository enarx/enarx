// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::fmt::{Debug, Formatter};

impl<U> PrivateKey<U> {
    pub(crate) fn derive(&self, cert: &sev::Certificate) -> Result<Vec<u8>> {
        let key = PublicKey::try_from(cert)?;
        let mut der = derive::Deriver::new(&self.key)?;
        der.set_peer(&key.key)?;
        Ok(der.derive_to_vec()?)
    }
}

macro_rules! prv_decoder {
    ($($cert:path => $usage:path),+) => {
        $(
            impl codicon::Decoder<&$cert> for PrivateKey<$usage> {
                type Error = Error;

                fn decode(reader: &mut impl Read, params: &$cert) -> Result<Self> {
                    let mut buf = Vec::new();
                    reader.read_to_end(&mut buf)?;

                    let prv = pkey::PKey::private_key_from_der(&buf)?;
                    let key = PublicKey::try_from(params)?;
                    if !prv.public_eq(&key.key) {
                        return Err(ErrorKind::InvalidData.into());
                    }

                    Ok(PrivateKey {
                        usage: key.usage,
                        hash: key.hash,
                        id: key.id,
                        key: prv,
                    })
                }
            }
        )+
    };
}

prv_decoder! {
    sev::Certificate => sev::Usage,
    ca::Certificate => ca::Usage
}

impl<U> codicon::Encoder for PrivateKey<U> {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<()> {
        let buf = self.key.private_key_to_der()?;
        writer.write_all(&buf)
    }
}

impl<U: Copy + Into<Usage>> std::fmt::Display for PublicKey<U> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use std::fmt::Error;

        let sig = match self.usage.into() {
            Usage::CEK | Usage::OCA | Usage::PEK => true,
            Usage::ARK | Usage::ASK => true,
            _ => false,
        };

        match (sig, self.key.id()) {
            (true, pkey::Id::RSA) => write!(
                f,
                "R{} R{}",
                self.key.rsa()?.size() * 8,
                self.hash.size() * 8
            ),

            (true, pkey::Id::EC) => write!(
                f,
                "EP{} E{}",
                self.key.ec_key()?.group().degree(),
                self.hash.size() * 8
            ),

            (false, pkey::Id::EC) => write!(
                f,
                "EP{} D{}",
                self.key.ec_key()?.group().degree(),
                self.hash.size() * 8
            ),

            _ => Err(Error),
        }
    }
}

impl<U> PublicKey<U>
where
    U: Debug,
    Usage: PartialEq<U>,
{
    pub fn verify(
        &self,
        msg: &impl codicon::Encoder<Body, Error = Error>,
        sig: &Signature,
    ) -> Result<()> {
        let usage = sig.usage == self.usage;
        let kind = sig.kind == self.key.id();
        let hash = sig.hash == self.hash;
        let id = sig.id.is_none() || sig.id == self.id;
        if !usage || !kind || !hash || !id {
            return Err(ErrorKind::InvalidInput.into());
        }

        let mut ver = sign::Verifier::new(sig.hash, &self.key)?;
        if self.key.id() == pkey::Id::RSA {
            ver.set_rsa_padding(rsa::Padding::PKCS1_PSS)?;
            ver.set_rsa_pss_saltlen(sign::RsaPssSaltlen::DIGEST_LENGTH)?;
        }

        msg.encode(&mut ver, Body)?;
        ver.verify(&sig.sig).map(|ok| {
            // OpenSSL's verify will return Ok(true) if the signature
            // is verified and Ok(false) if not. This patches the result
            // to return Err if OpenSSL returns Ok(false).
            if ok {
                Ok(())
            } else {
                Err(ErrorKind::NotFound.into())
            }
        })?
    }
}
