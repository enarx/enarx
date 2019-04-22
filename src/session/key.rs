use std::ops::{Deref, DerefMut};
use std::ptr::write_volatile;
use std::convert::*;
use super::*;

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

        for i in 1 ..= (size + hbytes - 1) / hbytes {
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
