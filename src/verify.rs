use std::collections::HashMap;
use std::hash::BuildHasher;
use ring::signature::*;
use untrusted::Input;
use super::*;

impl PublicKey {
    fn is_signer(&self, sig: &super::Signature) -> bool {
        let id = sig.id.is_none() || sig.id == self.id;
        self.usage == sig.usage && self.algo == sig.algo && id
    }

    fn algorithm(&self) -> Option<&dyn ring::signature::VerificationAlgorithm> {
        Some(match self.algo {
            Algo::Sig(SigAlgo::RsaSha256) => &RSA_PSS_2048_8192_SHA256,
            Algo::Sig(SigAlgo::RsaSha384) => &RSA_PSS_2048_8192_SHA384,

            Algo::Sig(SigAlgo::EcdsaSha256) => {
                match self.key {
                    Key::Rsa(_) => return None,
                    Key::Ecc(ref e) => match e.curve {
                        Curve::P256 => &ECDSA_P256_SHA256_FIXED,
                        Curve::P384 => &ECDSA_P384_SHA256_FIXED,
                    }
                }
            },

            Algo::Sig(SigAlgo::EcdsaSha384) => {
                match self.key {
                    Key::Rsa(_) => return None,
                    Key::Ecc(ref e) => match e.curve {
                        Curve::P256 => &ECDSA_P256_SHA384_FIXED,
                        Curve::P384 => &ECDSA_P384_SHA384_FIXED,
                    }
                }
            },

            _ => return None, // Not a signing algorithm
        })
    }

    fn verify(&self, cert: &Certificate) -> Result<(), ()> {
        let sig = cert.sigs.iter().find(|s| self.is_signer(s)).ok_or(())?;
        let sig = (&self.key, sig).encode_buf(Ring).or(Err(()))?;
        let sig = Input::from(&sig);

        let msg = cert.encode_buf(Ring).or(Err(()))?;
        let msg = Input::from(&msg);

        let key = self.key.encode_buf(Ring).or(Err(()))?;
        let key = Input::from(&key);

        let alg = self.algorithm().ok_or(())?;

        verify(alg, key, msg, sig).or(Err(()))
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
