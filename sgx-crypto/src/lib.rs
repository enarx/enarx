// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![deny(clippy::all)]
#![allow(clippy::identity_op)]
#![allow(clippy::unreadable_literal)]
#![deny(missing_docs)]

use openssl::{bn, hash, pkey, rsa, sha, sign};
use sgx_types::{page, sig};
use std::convert::TryInto;
use std::io::Result;
use std::num::NonZeroU32;

/// This struct creates and updates the MRENCLAVE value associated
/// with an enclave's Signature (or SIGSTRUCT). This value is updated with
/// each ECREATE, EADD, or EEXTEND operation as documented in 41.3 and as
/// summarized at https://github.com/enarx/enarx/wiki/SGX-Measurement. The leaf
/// functions are mimicked to obtain these values, but are not actually called here;
/// to use them, refer to the [iocuddle-sgx](../../iocuddle-sgx) library.
pub struct Hasher(sha::Sha256);

impl Hasher {
    /// Mimics call to SGX_IOC_ENCLAVE_CREATE (ECREATE).
    pub fn new(size: usize, ssa_pages: NonZeroU32) -> Self {
        let size = size as u64;

        // This value documented in 41.3.
        const ECREATE: u64 = 0x0045544145524345;

        let mut sha256 = sha::Sha256::new();
        sha256.update(&ECREATE.to_le_bytes());
        sha256.update(&ssa_pages.get().to_le_bytes());
        sha256.update(&size.to_le_bytes());
        sha256.update(&[0u8; 44]); // Reserved

        Self(sha256)
    }

    /// Mimics call to SGX_IOC_ENCLAVE_ADD_PAGES (EADD and EEXTEND).
    pub fn add<T: AsRef<[u8]> + ?Sized>(
        &mut self,
        data: &T,
        offset: usize,
        secinfo: page::SecInfo,
        measure: bool,
    ) {
        let data = data.as_ref();

        // These values documented in 41.3.
        const EEXTEND: u64 = 0x00444E4554584545;
        const EADD: u64 = 0x0000000044444145;

        assert_eq!(data.len() % 4096, 0);
        assert_eq!(offset % 4096, 0);

        // For each page in the input...
        for (i, page) in data.chunks(4096).enumerate() {
            let off = offset + i * 4096;

            // Hash for the EADD instruction.
            self.0.update(&EADD.to_le_bytes());
            self.0.update(&(off as u64).to_le_bytes());
            self.0.update(&secinfo.as_ref()[..48]);

            // Hash for the EEXTEND instruction.
            if measure {
                for (j, segment) in page.chunks(256).enumerate() {
                    let off = off + j * 256;

                    self.0.update(&EEXTEND.to_le_bytes());
                    self.0.update(&(off as u64).to_le_bytes());
                    self.0.update(&[0u8; 48]);
                    self.0.update(segment);
                }
            }
        }
    }

    /// Produces MRENCLAVE value by hashing with SHA256.
    pub fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

trait ToArray {
    fn to_le_array(&self) -> Result<[u8; 384]>;
}

impl ToArray for bn::BigNumRef {
    #[allow(clippy::uninit_assumed_init)]
    fn to_le_array(&self) -> Result<[u8; 384]> {
        use std::mem::MaybeUninit;

        let mut buf: [u8; 384] = unsafe { MaybeUninit::uninit().assume_init() };
        self.to_le_bytes(&mut buf)?;
        Ok(buf)
    }
}

/// When implemented for the sig::Signature struct from [sgx-types](../../sgx-types),
/// this trait signs the MRENCLAVE value created
/// by the Hasher with an RSA key, as documented in 38.13.
pub trait Signature: Sized {
    /// Returns a signature over an Author (SIGSTRUCT header) and SIGSTRUCT Contents
    /// with the provided RSA key.
    fn sign(
        author: sig::Author,
        contents: sig::Contents,
        key: rsa::Rsa<pkey::Private>,
    ) -> Result<Self>;
}

impl Signature for sig::Signature {
    fn sign(
        author: sig::Author,
        contents: sig::Contents,
        key: rsa::Rsa<pkey::Private>,
    ) -> Result<Self> {
        let a = unsafe {
            core::slice::from_raw_parts(
                &author as *const _ as *const u8,
                core::mem::size_of_val(&author),
            )
        };

        let c = unsafe {
            core::slice::from_raw_parts(
                &contents as *const _ as *const u8,
                core::mem::size_of_val(&contents),
            )
        };

        // Generates signature on Signature author and contents
        let rsa_key = pkey::PKey::from_rsa(key.clone())?;
        let md = hash::MessageDigest::sha256();
        let mut signer = sign::Signer::new(md, &rsa_key)?;
        signer.update(a)?;
        signer.update(c)?;
        let signature = signer.sign_to_vec()?;

        // Generates q1, q2 values for RSA signature verification
        let s = bn::BigNum::from_be_bytes(&signature)?;
        let m = key.n();

        let mut ctx = bn::BigNumContext::new()?;
        let mut q1 = bn::BigNum::new()?;
        let mut qr = bn::BigNum::new()?;

        q1.div_rem(&mut qr, &(&s * &s), &m, &mut ctx)?;
        let q2 = &(&s * &qr) / m;

        Ok(sig::Signature::new(
            author,
            contents,
            key.e().try_into()?,
            m.to_le_array()?,
            s.to_le_array()?,
            q1.to_le_array()?,
            q2.to_le_array()?,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sgx_types::page::{Flags as Perms, SecInfo};
    use sgx_types::sig;
    use std::fs::File;
    use std::io::Read;

    // A NOTE ABOUT THIS TESTING METHODOLOGY
    //
    // The ANSWER values in this test are not guaranteed to be correct.
    // They were produced by getting the hasher to output the same hash
    // for the binary from the Linux kernel SGX selftest and then running
    // the algorithm again to produce these ANSWERs. At least some of the
    // ANSWERs are correct. The remaining ones alert us to algorithmic
    // changes. We expect that over time our ANSWERs will be correct.
    //
    // The canonical source of correctness for this algorithm is, of
    // course, the Intel SGX CPU/microcode/ME. If you can demonstrate a
    // a case where we don't match this, we will happily change our ANSWERs.

    const DATA: [u8; 4096] = [123u8; 4096];
    const LONG: [u8; 8192] = [123u8; 8192];

    fn hash(input: &[(&[u8], SecInfo)]) -> [u8; 32] {
        // Add the lengths of all the enclave segments to produce enclave size.
        let size = input.iter().fold(0, |c, x| c + x.0.len());

        // Inputs:
        //   enclave size: the next power of two beyond our segments
        //      ssa pages: 1
        let ssa_pages = NonZeroU32::new(1).unwrap();
        let mut hasher = Hasher::new(size.next_power_of_two(), ssa_pages);

        let mut off = 0;
        for i in input {
            hasher.add(i.0, off, i.1, true);
            off += i.0.len();
        }

        hasher.finish()
    }

    #[test]
    fn empty() {
        const ANSWER: [u8; 32] = [
            252, 149, 215, 52, 58, 111, 14, 95, 207, 19, 57, 38, 97, 120, 23, 26, 207, 44, 152, 5,
            72, 202, 97, 25, 204, 94, 10, 197, 188, 89, 246, 246,
        ];
        let question = hash(&[]);
        assert_eq!(question, ANSWER);
    }

    #[test]
    fn tcs() {
        const ANSWER: [u8; 32] = [
            230, 83, 134, 171, 179, 130, 94, 239, 114, 13, 202, 111, 173, 126, 101, 185, 44, 96,
            129, 56, 92, 7, 246, 99, 17, 85, 245, 207, 201, 9, 51, 65,
        ];
        let question = hash(&[(&DATA, SecInfo::tcs())]);
        assert_eq!(question, ANSWER);
    }

    #[test]
    fn r() {
        const ANSWER: [u8; 32] = [
            0, 117, 112, 212, 9, 215, 100, 12, 99, 30, 102, 236, 187, 103, 39, 144, 251, 33, 191,
            112, 25, 95, 140, 251, 201, 209, 113, 187, 15, 71, 15, 242,
        ];
        let question = hash(&[(&DATA, SecInfo::reg(Perms::R))]);
        assert_eq!(question, ANSWER);
    }

    #[test]
    fn rw() {
        const ANSWER: [u8; 32] = [
            129, 184, 53, 91, 133, 145, 39, 205, 176, 182, 220, 37, 36, 198, 139, 91, 148, 181, 98,
            116, 22, 122, 174, 173, 173, 59, 39, 209, 165, 47, 8, 219,
        ];
        let question = hash(&[(&DATA, SecInfo::reg(Perms::R | Perms::W))]);
        assert_eq!(question, ANSWER);
    }

    #[test]
    fn rwx() {
        const ANSWER: [u8; 32] = [
            175, 209, 233, 45, 48, 189, 118, 146, 139, 110, 63, 192, 56, 119, 66, 69, 246, 116,
            142, 206, 58, 97, 186, 173, 59, 110, 122, 19, 171, 237, 80, 6,
        ];
        let question = hash(&[(&DATA, SecInfo::reg(Perms::R | Perms::W | Perms::X))]);
        assert_eq!(question, ANSWER);
    }

    #[test]
    fn rx() {
        const ANSWER: [u8; 32] = [
            76, 207, 169, 240, 107, 1, 166, 236, 108, 53, 91, 107, 135, 238, 123, 132, 35, 246,
            230, 31, 254, 6, 3, 175, 35, 2, 39, 175, 114, 254, 73, 55,
        ];
        let question = hash(&[(&DATA, SecInfo::reg(Perms::R | Perms::X))]);
        assert_eq!(question, ANSWER);
    }

    #[test]
    fn long() {
        const ANSWER: [u8; 32] = [
            233, 11, 17, 35, 117, 163, 196, 106, 142, 137, 169, 130, 108, 108, 51, 5, 29, 241, 152,
            190, 9, 245, 27, 16, 85, 173, 17, 90, 43, 124, 46, 84,
        ];
        let question = hash(&[(&DATA, SecInfo::tcs()), (&LONG, SecInfo::reg(Perms::R))]);
        assert_eq!(question, ANSWER);
    }

    fn load(path: &str) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        let size = file.metadata().unwrap().len();

        let mut data = vec![0u8; size as usize];
        file.read_exact(&mut data).unwrap();

        data
    }

    fn loadsig(path: &str) -> sig::Signature {
        let mut sig: sig::Signature;
        let buf: &mut [u8];

        unsafe {
            sig = std::mem::MaybeUninit::uninit().assume_init();
            buf = std::slice::from_raw_parts_mut(
                &mut sig as *mut _ as *mut u8,
                std::mem::size_of_val(&sig),
            );
        }

        let mut file = File::open(path).unwrap();
        file.read_exact(buf).unwrap();

        sig
    }

    fn loadkey(path: &str) -> rsa::Rsa<pkey::Private> {
        let pem = load(path);
        rsa::Rsa::private_key_from_pem(&pem).unwrap()
    }

    #[test]
    fn selftest() {
        let bin = load("tests/encl.bin");
        let sig = loadsig("tests/encl.ss");
        let key = loadkey("tests/encl.pem");

        // Validate the hash.
        assert_eq!(
            sig.contents.mrenclave,
            hash(&[
                (&bin[..4096], SecInfo::tcs()),
                (&bin[4096..], SecInfo::reg(Perms::R | Perms::W | Perms::X))
            ]),
            "failed to produce correct mrenclave hash"
        );

        // Ensure that sign() can reproduce the exact same signature struct.
        assert_eq!(
            sig,
            sig::Signature::sign(sig.author, sig.contents, key).unwrap(),
            "failed to produce correct signature"
        );
    }
}
