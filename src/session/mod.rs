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

    pub fn session(self) -> Result<Session<Initialized>> {
        Ok(session::Session {
            policy: self,
            tek: key::Key::random(16)?,
            tik: key::Key::random(16)?,
            data: Initialized,
        })
    }
}

impl Session<Initialized> {
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
            data: launch::Data {
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
        sig.update(&[build.version.major, build.version.minor, build.build])?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify() {
        let digest = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        ];

        let measurement = launch::Measurement {
            measure: [
                0x6f, 0xaa, 0xb2, 0xda, 0xae, 0x38, 0x9b, 0xcd,
                0x34, 0x05, 0xa0, 0x5d, 0x6c, 0xaf, 0xe3, 0x3c,
                0x04, 0x14, 0xf7, 0xbe, 0xdd, 0x0b, 0xae, 0x19,
                0xba, 0x5f, 0x38, 0xb7, 0xfd, 0x16, 0x64, 0xea
            ],
            mnonce: [
                0x4f, 0xbe, 0x0b, 0xed, 0xba, 0xd6, 0xc8, 0x6a,
                0xe8, 0xf6, 0x89, 0x71, 0xd1, 0x03, 0xe5, 0x54
            ],
        };

        let session = Session {
            policy: launch::Policy {
                flags: launch::PolicyFlags::default(),
                minfw: Version::new(0, 0),
            },
            tek: key::Key::random(16).unwrap(),
            tik: key::Key::new(vec![
                0x66, 0x32, 0x0d, 0xb7, 0x31, 0x58, 0xa3, 0x5a,
                0x25, 0x5d, 0x05, 0x17, 0x58, 0xe9, 0x5e, 0xd4
            ]),
            data: Initialized
        };

        let build = Build::new(0x00, 0x12, 0x0f);

        session.verify(&digest, build, measurement).unwrap();
    }
}
