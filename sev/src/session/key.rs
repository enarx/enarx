// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::convert::*;
use std::ops::{Deref, DerefMut};
use std::ptr::write_volatile;

use openssl::*;

#[repr(transparent)]
pub struct Key(Vec<u8>);

impl Drop for Key {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            unsafe {
                write_volatile(b as *mut u8, 0u8);
            }
        }
    }
}

impl Deref for Key {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for Key {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Key {
    pub fn new(key: Vec<u8>) -> Self {
        Self(key)
    }

    pub fn zeroed(size: usize) -> Self {
        Key(vec![0u8; size])
    }

    pub fn random(size: usize) -> Result<Self> {
        let mut key = Key::zeroed(size);
        rand::rand_bytes(&mut key)?;
        Ok(key)
    }
}

impl Key {
    // NIST 800-108 5.1 - KDF in Counter Mode
    pub fn derive(&self, size: usize, ctx: &[u8], label: &str) -> Result<Key> {
        let hsh = hash::MessageDigest::sha256();
        let key = pkey::PKey::hmac(self)?;

        let hbytes = hsh.size();
        let _ = u32::try_from(hbytes * 8).or(Err(ErrorKind::InvalidInput))?;
        let lbits = u32::try_from(size * 8).or(Err(ErrorKind::InvalidInput))?;

        let mut out = Key::zeroed((size + hbytes - 1) / hbytes * hbytes);
        let mut buf = &mut out[..];

        for i in 1..=((size + hbytes - 1) / hbytes) as u32 {
            let mut sig = sign::Signer::new(hsh, &key)?;

            sig.update(&i.to_le_bytes())?;
            sig.update(label.as_bytes())?;
            sig.update(&[0u8])?;
            sig.update(ctx)?;
            sig.update(&lbits.to_le_bytes())?;

            sig.sign(buf)?;
            buf = &mut buf[hbytes..];
        }

        out.0.truncate(size);
        Ok(out)
    }

    pub fn mac(&self, data: &[u8]) -> Result<[u8; 32]> {
        let mut mac = [0u8; 32];
        let key = pkey::PKey::hmac(self)?;
        let mut sig = sign::Signer::new(hash::MessageDigest::sha256(), &key)?;

        sig.update(data)?;
        sig.sign(&mut mac)?;
        Ok(mac)
    }
}

#[cfg(test)]
#[test]
fn derive() {
    let master = Key::zeroed(16)
        .derive(16, &[0u8; 16], "sev-master-secret")
        .unwrap();
    assert_eq!(
        master.0,
        vec![
            0xab, 0x4d, 0x26, 0x9f, 0xcc, 0x62, 0xbe, 0xdb, 0x45, 0x11, 0xd5, 0x6c, 0x38, 0x6c,
            0xe7, 0x06,
        ]
    )
}

#[cfg(test)]
#[test]
fn mac() {
    let mac = Key::zeroed(16).mac(&[0u8; 4]).unwrap();
    assert_eq!(
        mac,
        [
            0xaa, 0x78, 0x55, 0xe1, 0x38, 0x39, 0xdd, 0x76, 0x7c, 0xd5, 0xda, 0x7c, 0x1f, 0xf5,
            0x03, 0x65, 0x40, 0xc9, 0x26, 0x4b, 0x7a, 0x80, 0x30, 0x29, 0x31, 0x5e, 0x55, 0x37,
            0x52, 0x87, 0xb4, 0xaf,
        ]
    )
}
