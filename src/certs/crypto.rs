use std::collections::HashMap;
use std::hash::BuildHasher;
use std::num::NonZeroU128;
use super::*;

use openssl::pkey::{PKey, Public, Private};
use openssl::bn::{BigNumContext, BigNum};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;
use openssl::rand::rand_bytes;
use openssl::ecdsa::EcdsaSig;
use openssl::rsa::Rsa;
use openssl::nid::Nid;

fn bn(buf: &[u8]) -> Result<BigNum, ErrorStack> {
    BigNum::from_slice(&buf.iter().rev().cloned()
        .skip_while(|b| *b == 0)
        .collect::<Vec<u8>>())
}

impl RsaKey {
    fn generate(bits: u32) -> Result<(RsaKey, PKey<Private>), ErrorStack> {
        let prv = Rsa::generate(bits)?;

        let mut pubexp = [0u8; 4096 / 8];
        for (i, b) in prv.e().to_vec().iter().rev().enumerate() {
            pubexp[i] = *b;
        }

        let mut modulus = [0u8; 4096 / 8];
        for (i, b) in prv.n().to_vec().iter().rev().enumerate() {
            modulus[i] = *b;
        }

        Ok((RsaKey { pubexp, modulus }, PKey::from_rsa(prv)?))
    }
}

impl Curve {
    fn group(&self) -> Result<EcGroup, ErrorStack> {
        Ok(EcGroup::from_curve_name(match self {
            Curve::P256 => Nid::X9_62_PRIME256V1,
            Curve::P384 => Nid::SECP384R1,
        })?)
    }
}

impl EccKey {
    fn generate(c: Curve) -> Result<(EccKey, PKey<Private>), ErrorStack> {
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

        Ok((EccKey { c, x, y }, PKey::from_ec_key(prv)?))
    }
}

impl Usage {
    fn generate(self) -> Result<(Key, PKey<Private>), ErrorStack> {
        match self {
            Usage::AmdRootKey | Usage::AmdSevKey => {
                let (key, prv) = RsaKey::generate(2048)?;
                Ok((Key::Rsa(key), prv))
            },

            _ => {
                let (key, prv) = EccKey::generate(Curve::P384)?;
                Ok((Key::Ecc(key), prv))
            },
        }
    }

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

    fn firmware(self) -> Option<Firmware> {
        match self {
            Usage::AmdRootKey | Usage::AmdSevKey => None,
            _ => Some(Firmware(0, 0)),
        }
    }
}

impl Key {
    fn pkey(&self) -> Result<PKey<Public>, ErrorStack> {
        match self {
            Key::Rsa(ref r) => {
                let n = bn(&r.modulus)?;
                let e = bn(&r.pubexp)?;
                let k = Rsa::from_public_components(n, e)?;
                PKey::from_rsa(k)
            },

            Key::Ecc(ref e) => {
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
    fn is_signer(&self, sig: &super::Signature) -> bool {
        let id = sig.id.is_none() || sig.id == self.id;
        self.usage == sig.usage && self.algo == sig.algo && id
    }

    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), ()> {
        let key = self.key.pkey().or(Err(()))?;
        let hsh = sig.algo.hash();

        let mut ver = openssl::sign::Verifier::new(hsh, &key).or(Err(()))?;
        ver.update(&msg).or(Err(()))?;
        ver.verify(&sig.format().or(Err(()))?).and(Ok(())).or(Err(()))
    }

    fn sign(&self, pkey: &PKey<Private>, msg: &[u8]) -> Result<Signature, ()> {
        let algo = match self.algo {
            Algo::Sig(a) => a,
            _ => Err(())?,
        };

        let mut sig = openssl::sign::Signer::new(algo.hash(), &pkey).or(Err(()))?;
        sig.update(msg).or(Err(()))?;
        let sig = sig.sign_to_vec().or(Err(()))?;

        let sig = Signature {
            sig: Signature::unformat(algo, &sig).or(Err(()))?,
            usage: self.usage,
            id: self.id,
            algo,
        };

        self.verify(msg, &sig).or(Err(()))?;
        Ok(sig)
    }
}

impl Certificate {
    pub fn sign(&self, prv: &[u8], crt: &mut Certificate) -> Result<(), ()> {
        let prv = PKey::private_key_from_der(prv).or(Err(()))?;
        let msg = crt.body().or(Err(()))?;
        let sig = self.key.sign(&prv, &msg)?;

        if crt.sigs[0].is_none() {
            crt.sigs[0] = Some(sig);
        } else if crt.sigs[1].is_none() {
            crt.sigs[1] = Some(sig);
        } else {
            Err(())?
        }

        Ok(())
    }

    pub fn new(usage: Usage) -> Result<(Certificate, Vec<u8>), ()> {
        let (key, prv) = usage.generate().or(Err(()))?;

        let mut crt = Certificate {
            version: 1,
            firmware: usage.firmware(),
            sigs: [None, None],
            key: PublicKey {
                id: usage.id().or(Err(()))?,
                algo: usage.algo(),
                usage,
                key
            }
        };

        let msg = crt.body().or(Err(()))?;
        let sig = crt.key.sign(&prv, &msg)?;
        crt.sigs[0] = Some(sig);

        Ok((crt, prv.private_key_to_der().or(Err(()))?))
    }

    fn find<'a>(&self, other: &'a Certificate) -> Result<&'a Signature, ()> {
        if let Some(ref s) = other.sigs[0] {
            if self.key.is_signer(s) {
                return Ok(s);
            }
        }

        if let Some(ref s) = other.sigs[1] {
            if self.key.is_signer(s) {
                return Ok(s);
            }
        }

        Err(())
    }
}

impl<'a> Verifier<'a> for (&Certificate, &'a Certificate) {
    fn verify(self) -> Result<&'a Certificate, ()> {
        let sig = self.0.find(&self.1)?;
        let msg = self.1.body().or(Err(()))?;
        self.0.key.verify(&msg, sig).and(Ok(self.1))
    }
}

impl<'a> Verifier<'a> for &[&'a Certificate] {
    fn verify(self) -> Result<&'a Certificate, ()> {
        let root = *self.first().ok_or(())?;
        Ok(self.iter().try_fold(root, |a, &b| (a, b).verify())?)
    }
}

impl<'a, S: BuildHasher> Verifier<'a> for &'a HashMap<Usage, Certificate, S> {
    fn verify(self) -> Result<&'a Certificate, ()> {
        let oca = self.get(&Usage::OwnerCertificateAuthority).ok_or(())?;
        let ark = self.get(&Usage::AmdRootKey).ok_or(())?;
        let ask = self.get(&Usage::AmdSevKey).ok_or(())?;
        let cek = self.get(&Usage::ChipEndorsementKey).ok_or(())?;
        let pek = self.get(&Usage::PlatformEndorsementKey).ok_or(())?;
        let pdh = self.get(&Usage::PlatformDiffieHellman).ok_or(())?;

        [ark, ask, cek, [oca, pek].verify()?, pdh].verify()
    }
}
