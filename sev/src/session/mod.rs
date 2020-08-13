// SPDX-License-Identifier: Apache-2.0

mod key;

use super::*;
use openssl::*;
use std::io::*;

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
    fn session(&self, nonce: [u8; 16], iv: [u8; 16], z: key::Key) -> Result<launch::Session> {
        let master = z.derive(16, &nonce, "sev-master-secret")?;
        let kek = master.derive(16, &[], "sev-kek")?;
        let kik = master.derive(16, &[], "sev-kik")?;

        let mut crypter = symm::Crypter::new(
            symm::Cipher::aes_128_ctr(),
            symm::Mode::Encrypt,
            &kek,
            Some(&iv),
        )?;

        let mut wrap = [0u8; 32];
        let mut off = 0;
        off += crypter.update(&*self.tek, &mut wrap[off..])?;
        off += crypter.update(&*self.tik, &mut wrap[off..])?;
        off += crypter.finalize(&mut wrap[off..])?;
        assert_eq!(off, wrap.len());

        let wmac = kik.mac(&wrap)?;
        let pmac = self.tik.mac(&self.policy.bytes())?;

        Ok(launch::Session {
            policy_mac: pmac,
            wrap_mac: wmac,
            wrap_tk: wrap,
            wrap_iv: iv,
            nonce,
        })
    }

    pub fn start(&self, chain: certs::Chain) -> Result<launch::Start> {
        use certs::*;

        let pdh = chain.verify()?;
        let (crt, prv) = sev::Certificate::generate(sev::Usage::PDH)?;

        let z = key::Key::new(prv.derive(&pdh)?);
        let mut nonce = [0u8; 16];
        let mut iv = [0u8; 16];
        rand::rand_bytes(&mut nonce)?;
        rand::rand_bytes(&mut iv)?;

        Ok(launch::Start {
            policy: self.policy,
            cert: crt,
            session: self.session(nonce, iv, z)?,
        })
    }

    pub fn measure(self) -> Result<Session<Measuring>> {
        Ok(Session {
            policy: self.policy,
            tek: self.tek,
            tik: self.tik,
            data: Measuring(hash::Hasher::new(hash::MessageDigest::sha256())?),
        })
    }

    pub fn verify(
        self,
        digest: &[u8],
        build: Build,
        msr: launch::Measurement,
    ) -> Result<Session<Verified>> {
        let key = pkey::PKey::hmac(&*self.tik)?;
        let mut sig = sign::Signer::new(hash::MessageDigest::sha256(), &key)?;

        sig.update(&[0x04u8])?;
        sig.update(&[build.version.major, build.version.minor, build.build])?;
        sig.update(&self.policy.bytes())?;
        sig.update(&digest)?;
        sig.update(&msr.mnonce)?;

        if sig.sign_to_vec()? != msr.measure {
            return Err(ErrorKind::InvalidInput.into());
        }

        Ok(Session {
            policy: self.policy,
            tek: self.tek,
            tik: self.tik,
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
            policy: self.policy,
            tek: self.tek,
            tik: self.tik,
            data: Initialized,
        };

        session.verify(&digest, build, msr)
    }
}

impl Session<Verified> {
    pub fn secret(&self, flags: launch::HeaderFlags, data: &[u8]) -> Result<launch::Secret> {
        let mut iv = [0u8; 16];
        rand::rand_bytes(&mut iv)?;

        let ciphertext = symm::encrypt(symm::Cipher::aes_128_ctr(), &*self.tek, Some(&iv), data)?;

        let key = pkey::PKey::hmac(&*self.tik)?;
        let mut sig = sign::Signer::new(hash::MessageDigest::sha256(), &key)?;

        sig.update(&[0x01u8])?;
        sig.update(&unsafe { std::mem::transmute::<_, [u8; 4]>(flags) })?;
        sig.update(&iv)?;
        sig.update(&(data.len() as u32).to_le_bytes())?;
        sig.update(&(ciphertext.len() as u32).to_le_bytes())?;
        sig.update(&ciphertext)?;
        sig.update(&self.data.0.measure)?;

        let mut mac = [0u8; 32];
        sig.sign(&mut mac)?;

        Ok(launch::Secret {
            header: launch::Header { flags, mac, iv },
            ciphertext,
        })
    }
}

#[cfg(test)]
mod initialized {
    use super::*;
    use crate::{launch, session::Session, Build, Version};

    #[test]
    fn session() {
        let session = Session {
            policy: launch::Policy::default(),
            tek: key::Key::new(vec![0u8; 16]),
            tik: key::Key::new(vec![0u8; 16]),
            data: Initialized,
        };

        let launch = session
            .session([0u8; 16], [0u8; 16], key::Key::zeroed(16))
            .unwrap();

        assert_eq!(launch.wrap_iv, [0u8; 16]);

        assert_eq!(launch.nonce, [0u8; 16]);

        assert_eq!(
            launch.wrap_tk,
            [
                0x21, 0x37, 0xbc, 0x7f, 0x9b, 0xb8, 0xbd, 0x7c, 0x3e, 0x55, 0xa5, 0x76, 0xa1, 0x5d,
                0x34, 0x54, 0xb3, 0x85, 0x6b, 0x8b, 0xa2, 0x7a, 0xfa, 0xdf, 0x46, 0xdc, 0xfe, 0xe9,
                0xf0, 0x2c, 0x02, 0xc4,
            ]
        );

        assert_eq!(
            launch.wrap_mac,
            [
                0x31, 0x76, 0xc0, 0x75, 0x27, 0x38, 0xbd, 0x9d, 0x5e, 0x86, 0x68, 0x95, 0x34, 0x02,
                0x0f, 0x52, 0x8c, 0x08, 0x8f, 0x16, 0x23, 0x88, 0x26, 0xb0, 0x00, 0xb3, 0x27, 0xde,
                0xe6, 0xae, 0xed, 0x7d,
            ]
        );

        assert_eq!(
            launch.policy_mac,
            [
                0xaa, 0x78, 0x55, 0xe1, 0x38, 0x39, 0xdd, 0x76, 0x7c, 0xd5, 0xda, 0x7c, 0x1f, 0xf5,
                0x03, 0x65, 0x40, 0xc9, 0x26, 0x4b, 0x7a, 0x80, 0x30, 0x29, 0x31, 0x5e, 0x55, 0x37,
                0x52, 0x87, 0xb4, 0xaf,
            ]
        );
    }

    #[test]
    fn verify() {
        let digest = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];

        let measurement = launch::Measurement {
            measure: [
                0x6f, 0xaa, 0xb2, 0xda, 0xae, 0x38, 0x9b, 0xcd, 0x34, 0x05, 0xa0, 0x5d, 0x6c, 0xaf,
                0xe3, 0x3c, 0x04, 0x14, 0xf7, 0xbe, 0xdd, 0x0b, 0xae, 0x19, 0xba, 0x5f, 0x38, 0xb7,
                0xfd, 0x16, 0x64, 0xea,
            ],
            mnonce: [
                0x4f, 0xbe, 0x0b, 0xed, 0xba, 0xd6, 0xc8, 0x6a, 0xe8, 0xf6, 0x89, 0x71, 0xd1, 0x03,
                0xe5, 0x54,
            ],
        };

        let policy = launch::Policy {
            flags: launch::PolicyFlags::default(),
            minfw: Default::default(),
        };

        let tek = key::Key::new(vec![0u8; 16]);
        let tik = key::Key::new(vec![
            0x66, 0x32, 0x0d, 0xb7, 0x31, 0x58, 0xa3, 0x5a, 0x25, 0x5d, 0x05, 0x17, 0x58, 0xe9,
            0x5e, 0xd4,
        ]);

        let session = Session {
            policy,
            tek,
            tik,
            data: Initialized,
        };
        let build = Build {
            version: Version {
                major: 0x00,
                minor: 0x12,
            },
            build: 0x0f,
        };

        session.verify(&digest, build, measurement).unwrap();
    }
}
