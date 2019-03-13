use std::collections::HashMap;
use std::hash::BuildHasher;
use std::io::{Read, Write};
use std::num::NonZeroU128;
use super::*;

use openssl::pkey::{PKey, Public, Private};
use openssl::bn::{BigNumContext, BigNum};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::sign::RsaPssSaltlen;
use openssl::rsa::{Padding, Rsa};
use openssl::error::ErrorStack;
use openssl::rand::rand_bytes;
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;

use codicon::{Decoder, Encoder};

pub struct PrivateKey(PKey<Private>);

impl Decoder for PrivateKey {
    type Error = Error;

    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, Error> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let pkey = PKey::private_key_from_der(&buf)
            .or_else(|_| Err(Error::Invalid("private key".to_string())))?;

        Ok(PrivateKey(pkey))
    }
}

impl Encoder for PrivateKey {
    type Error = Error;

    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), Error> {
        let buf = self.0.private_key_to_der()
            .or_else(|_| Err(Error::Invalid("private key".to_string())))?;

        writer.write_all(&buf)?;
        Ok(())
    }
}

impl From<ErrorStack> for Unspecified {
    fn from(_: ErrorStack) -> Self {
        Unspecified
    }
}

fn bn(buf: &[u8]) -> Result<BigNum, ErrorStack> {
    BigNum::from_slice(&buf.iter().rev().cloned()
        .skip_while(|b| *b == 0)
        .collect::<Vec<u8>>())
}

impl RsaKey {
    pub fn generate(bits: usize) -> Result<(RsaKey, PrivateKey), Unspecified> {
        let bits = match bits {
            2048 => 2048,
            4096 => 4096,
            _ => Err(Unspecified)?,
        };

        let prv = Rsa::generate(bits)?;

        let mut pubexp = [0u8; 4096 / 8];
        for (i, b) in prv.e().to_vec().iter().rev().enumerate() {
            pubexp[i] = *b;
        }

        let mut modulus = [0u8; 4096 / 8];
        for (i, b) in prv.n().to_vec().iter().rev().enumerate() {
            modulus[i] = *b;
        }

        let prv = PKey::from_rsa(prv)?;
        Ok((RsaKey { pubexp, modulus }, PrivateKey(prv)))
    }
}

impl Curve {
    fn group(self) -> Result<EcGroup, ErrorStack> {
        Ok(EcGroup::from_curve_name(match self {
            Curve::P256 => Nid::X9_62_PRIME256V1,
            Curve::P384 => Nid::SECP384R1,
        })?)
    }
}

impl EccKey {
    pub fn generate(c: Curve) -> Result<(EccKey, PrivateKey), Unspecified> {
        let mut ctx = BigNumContext::new()?;
        let mut xn = BigNum::new()?;
        let mut yn = BigNum::new()?;

        let grp = c.group()?;
        let prv = EcKey::generate(&grp)?;

        prv.public_key().affine_coordinates_gfp(&grp, &mut xn, &mut yn, &mut ctx)?;

        let mut x = [0u8; 576 / 8];
        for (i, b) in xn.to_vec().iter().rev().enumerate() {
            x[i] = *b;
        }

        let mut y = [0u8; 576 / 8];
        for (i, b) in yn.to_vec().iter().rev().enumerate() {
            y[i] = *b;
        }

        let prv = PKey::from_ec_key(prv)?;
        Ok((EccKey { c, x, y }, PrivateKey(prv)))
    }
}

impl Usage {
    fn algo(self) -> Algo {
        match self {
            Usage::AmdRootKey | Usage::AmdSevKey => SigAlgo::RsaSha256.into(),
            Usage::PlatformDiffieHellman => ExcAlgo::EcdhSha256.into(),
            _ => SigAlgo::EcdsaSha256.into(),
        }
    }

    fn id(self) -> Result<Option<NonZeroU128>, ErrorStack> {
        let mut id = None;

        if self == Usage::AmdRootKey || self == Usage::AmdSevKey {
            while id.is_none() {
                let mut bytes = 0u128.to_ne_bytes();
                rand_bytes(&mut bytes)?;
                id = NonZeroU128::new(u128::from_ne_bytes(bytes));
            }
        }

        Ok(id)
    }

    pub fn generate(self) -> Result<(PublicKey, PrivateKey), Unspecified> {
        let (key, prv) = match self {
            Usage::AmdRootKey | Usage::AmdSevKey => {
                let (key, prv) = RsaKey::generate(2048)?;
                (KeyType::Rsa(key), prv)
            },

            _ => {
                let (key, prv) = EccKey::generate(Curve::P384)?;
                (KeyType::Ecc(key), prv)
            },
        };

        Ok((PublicKey {
            usage: self,
            algo: self.algo(),
            id: self.id()?,
            key: key
        }, prv))
    }
}

impl KeyType {
    fn pkey(&self) -> Result<PKey<Public>, ErrorStack> {
        match self {
            KeyType::Rsa(ref r) => {
                let n = bn(&r.modulus)?;
                let e = bn(&r.pubexp)?;
                let k = Rsa::from_public_components(n, e)?;
                PKey::from_rsa(k)
            },

            KeyType::Ecc(ref e) => {
                let g = EcGroup::from_curve_name(match e.c {
                    Curve::P256 => Nid::X9_62_PRIME256V1,
                    Curve::P384 => Nid::SECP384R1,
                })?;

                let x = bn(&e.x)?;
                let y = bn(&e.y)?;
                let k = EcKey::from_public_key_affine_coordinates(&g, &x, &y)?;
                PKey::from_ec_key(k)
            },
        }
    }
}

impl SigAlgo {
    fn hash(self) -> MessageDigest {
        match self {
            SigAlgo::EcdsaSha256 | SigAlgo::RsaSha256 => MessageDigest::sha256(),
            SigAlgo::EcdsaSha384 | SigAlgo::RsaSha384 => MessageDigest::sha384(),
        }
    }
}

impl ExcAlgo {
    fn hash(self) -> MessageDigest {
        match self {
            ExcAlgo::EcdhSha256 => MessageDigest::sha256(),
            ExcAlgo::EcdhSha384 => MessageDigest::sha384(),
        }
    }
}

impl Algo {
    fn hash(self) -> MessageDigest {
        match self {
            Algo::Sig(ref s) => s.hash(),
            Algo::Exc(ref e) => e.hash(),
        }
    }
}

impl Signature {
    fn unformat(algo: SigAlgo, buf: &[u8]) -> Result<[u8; 4096 / 8], ErrorStack> {
        let mut sig = [0u8; 4096 / 8];

        match algo {
            SigAlgo::RsaSha256 | SigAlgo::RsaSha384 => {
                for (i, b) in buf.iter().rev().enumerate() {
                    sig[i] = *b;
                }
            },

            SigAlgo::EcdsaSha256 | SigAlgo::EcdsaSha384 => {
                let e = EcdsaSig::from_der(&buf)?;

                for (i, b) in e.r().to_vec().iter().rev().enumerate() {
                    sig[..576 / 8][i] = *b;
                }

                for (i, b) in e.s().to_vec().iter().rev().enumerate() {
                    sig[576 / 8..][i] = *b;
                }
            },
        }

        Ok(sig)
    }

    fn format(&self) -> Result<Vec<u8>, ErrorStack> {
        match self.algo {
            SigAlgo::EcdsaSha256 | SigAlgo::EcdsaSha384 => {
                const SIZE: usize = 576 / 8;

                let r = bn(&self.sig[..SIZE])?;
                let s = bn(&self.sig[SIZE..][..SIZE])?;

                EcdsaSig::from_private_components(r, s)?.to_der()
            },

            SigAlgo::RsaSha256 | SigAlgo::RsaSha384 => {
                Ok(bn(&self.sig)?.to_vec())
            },
        }
    }
}

impl PublicKey {
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Unspecified> {
        let id = sig.id.is_none() || sig.id == self.id;
        if self.usage != sig.usage || self.algo != sig.algo || !id {
            Err(Unspecified)?
        }

        let key = self.key.pkey()?;
        let mut ver = openssl::sign::Verifier::new(sig.algo.hash(), &key)?;

        match sig.algo {
            SigAlgo::EcdsaSha256 | SigAlgo::EcdsaSha384 => (),
            SigAlgo::RsaSha256 | SigAlgo::RsaSha384 => {
                ver.set_rsa_padding(Padding::PKCS1_PSS)?;
                ver.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            }
        }

        ver.update(&msg)?;

        if ver.verify(&sig.format()?)? {
            Ok(())
        } else {
            Err(Unspecified)
        }
    }

    pub fn sign(&self, msg: &[u8], prv: &PrivateKey) -> Result<Signature, Unspecified> {
        let algo = match self.algo {
            Algo::Sig(a) => a,
            _ => Err(Unspecified)?,
        };

        let mut sig = openssl::sign::Signer::new(algo.hash(), &prv.0)?;

        match algo {
            SigAlgo::EcdsaSha256 | SigAlgo::EcdsaSha384 => (),
            SigAlgo::RsaSha256 | SigAlgo::RsaSha384 => {
                sig.set_rsa_padding(Padding::PKCS1_PSS)?;
                sig.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            }
        }

        sig.update(msg)?;
        let sig = sig.sign_to_vec()?;

        let sig = Signature {
            sig: Signature::unformat(algo, &sig)?,
            usage: self.usage,
            id: self.id,
            algo,
        };

        self.verify(msg, &sig)?;
        Ok(sig)
    }
}

impl std::fmt::Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let body = self.encode_buf(Body).unwrap();
        let algo = self.key.algo.hash();
        let hash = openssl::hash::hash(algo, &body)?;

        write!(f, "{} {} {} ", self.key.usage, self.key.key, self.key.algo)?;
        for b in hash.iter() {
            write!(f, "{:02x}", *b)?;
        }

        Ok(())
    }
}

impl<'a> Verifier<'a> for (&Certificate, &'a Certificate) {
    fn verify(self) -> Result<&'a Certificate, Unspecified> {
        let crt = self.1.encode_buf(Body)?;

        for sig in self.1.sigs.iter() {
            if let Some(ref s) = sig {
                if self.0.key.verify(&crt, s).is_ok() {
                    return Ok(self.1);
                }
            }
        }

        Err(Unspecified)
    }
}

impl<'a> Verifier<'a> for &[&'a Certificate] {
    fn verify(self) -> Result<&'a Certificate, Unspecified> {
        let root = *self.first().ok_or(Unspecified)?;
        Ok(self.iter().try_fold(root, |a, &b| (a, b).verify())?)
    }
}

impl<'a, S: BuildHasher> Verifier<'a> for &'a HashMap<Usage, Certificate, S> {
    fn verify(self) -> Result<&'a Certificate, Unspecified> {
        let oca = self.get(&Usage::OwnerCertificateAuthority).ok_or(Unspecified)?;
        let ark = self.get(&Usage::AmdRootKey).ok_or(Unspecified)?;
        let ask = self.get(&Usage::AmdSevKey).ok_or(Unspecified)?;
        let cek = self.get(&Usage::ChipEndorsementKey).ok_or(Unspecified)?;
        let pek = self.get(&Usage::PlatformEndorsementKey).ok_or(Unspecified)?;
        let pdh = self.get(&Usage::PlatformDiffieHellman).ok_or(Unspecified)?;

        [ark, ask, cek, [oca, pek].verify()?, pdh].verify()
    }
}
