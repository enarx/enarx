use std::collections::HashMap;
use std::hash::BuildHasher;
use super::*;

use openssl::pkey::{PKey, Public};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;
use openssl::ecdsa::EcdsaSig;
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use openssl::nid::Nid;

fn bn(buf: &[u8]) -> Result<BigNum, ErrorStack> {
    BigNum::from_slice(&buf.iter().rev().cloned()
        .skip_while(|b| *b == 0)
        .collect::<Vec<u8>>())
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
                let g = EcGroup::from_curve_name(match e.curve {
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

    fn verify(&self, cert: &Certificate) -> Result<(), ()> {
        let sig = cert.sigs.iter().find(|s| self.is_signer(s)).ok_or(())?;
        let key = self.key.pkey().or(Err(()))?;
        let msg = cert.body().or(Err(()))?;
        let hsh = sig.algo.hash();

        let mut ver = openssl::sign::Verifier::new(hsh, &key).or(Err(()))?;
        ver.update(&msg).or(Err(()))?;
        ver.verify(&sig.format().or(Err(()))?).and(Ok(())).or(Err(()))
    }
}

impl<'a> Verifier<'a> for (&Certificate, &'a Certificate) {
    fn verify(self) -> Result<&'a Certificate, ()> {
        self.0.key.verify(self.1).and(Ok(self.1))
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
