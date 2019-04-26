mod key;

use openssl::*;
use std::io::*;
use super::*;

pub struct Initialized;
pub struct Measuring(hash::Hasher);
pub struct Verified(launch::Measurement);

pub struct Session<T> {
    policy: launch::Policy,
    tek: key::Key,
    tik: key::Key,
    data: T,
}

impl launch::Policy {
    fn bytes(self) -> [u8; 4] {
        unsafe { std::mem::transmute(self) }
    }
}

impl std::convert::TryFrom<launch::Policy> for Session<Initialized> {
    type Error = std::io::Error;

    fn try_from(value: launch::Policy) -> Result<Self> {
        Ok(Self {
            tek: key::Key::random(16)?,
            tik: key::Key::random(16)?,
            data: Initialized,
            policy: value,
        })
    }
}

impl Session<Initialized> {
    pub fn from_keys(policy: launch::Policy, tek: Vec<u8>, tik: Vec<u8>) -> Self {
        Self {
            tek: key::Key::new(tek),
            tik: key::Key::new(tik),
            data: Initialized,
            policy,
        }
    }

    pub fn start(&self, chain: certs::Chain) -> Result<launch::Start> {
        use certs::*;

        let pdh = chain.verify()?;
        let (crt, prv) = sev::Certificate::generate(sev::Usage::PDH)?;

        let mut nonce = [0u8; 16];
        let mut iv = [0u8; 16];
        rand::rand_bytes(&mut nonce)?;
        rand::rand_bytes(&mut iv)?;

        let z = key::Key::new(prv.derive(&pdh)?);
        let master = z.derive(16, &nonce, "sev-master-secret")?;
        let kek = master.derive(16, &[], "sev-kek")?;
        let kik = master.derive(16, &[], "sev-kik")?;

        let mut crypter = symm::Crypter::new(
            symm::Cipher::aes_128_ctr(),
            symm::Mode::Encrypt, &kek, Some(&iv)
        )?;

        let mut wrap = [0u8; 32];
        let mut off = 0;
        off += crypter.update(&*self.tek, &mut wrap[off..])?;
        off += crypter.update(&*self.tik, &mut wrap[off..])?;
        off += crypter.finalize(&mut wrap[off..])?;
        assert_eq!(off, wrap.len());

        let wmac = kik.mac(&wrap)?;
        let pmac = kik.mac(&self.policy.bytes())?;

        Ok(launch::Start {
            policy: self.policy,
            cert: crt,
            session: launch::Session {
                policy_mac: pmac,
                wrap_mac: wmac,
                wrap_tk: wrap,
                wrap_iv: iv,
                nonce,
            }
        })
    }

    pub fn measure(self) -> Result<Session<Measuring>> {
        Ok(Session {
            policy: self.policy, tek: self.tek, tik: self.tik,
            data: Measuring(hash::Hasher::new(hash::MessageDigest::sha256())?)
        })
    }

    pub fn verify(self, digest: &[u8], build: Build, msr: launch::Measurement) -> Result<Session<Verified>> {
        let key = pkey::PKey::hmac(&*self.tik)?;
        let mut sig = sign::Signer::new(hash::MessageDigest::sha256(), &key)?;

        sig.update(&[0x04u8])?;
        sig.update(&[(build.0).0, (build.0).1, build.1])?;
        sig.update(&self.policy.bytes())?;
        sig.update(&digest)?;
        sig.update(&msr.mnonce)?;

        if sig.sign_to_vec()? != msr.measure {
            Err(ErrorKind::InvalidInput)?
        }

        Ok(Session {
            policy: self.policy, tek: self.tek, tik: self.tik,
            data: Verified(msr),
        })
    }
}

impl Session<Measuring> {
    pub fn update_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        Ok(self.data.0.update(data)?)
    }

    pub fn verify(mut self, build: Build, msr: launch::Measurement) -> Result<Session<Verified>> {
        let digest = self.data.0.finish()?;
        let session = Session {
            policy: self.policy, tek: self.tek, tik: self.tik,
            data: Initialized,
        };

        session.verify(&digest, build, msr)
    }
}

impl Session<Verified> {
    pub fn secret(&self, flags: launch::HeaderFlags, data: &[u8]) -> Result<launch::Secret> {
        let mut iv = [0u8; 16];
        rand::rand_bytes(&mut iv)?;

        let ciphertext = symm::encrypt(
            symm::Cipher::aes_128_ctr(),
            &*self.tek, Some(&iv), data
        )?;

        let mac = self.tik.mac(&ciphertext)?;

        Ok(launch::Secret {
            header: launch::Header { flags, mac, iv },
            ciphertext,
        })
    }
}
