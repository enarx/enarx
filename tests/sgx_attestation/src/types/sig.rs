// SPDX-License-Identifier: Apache-2.0

//! SigStruct (Section 38.13)
//! SigStruct is a structure created and signed by the enclave developer that
//! contains information about the enclave. SIGSTRUCT is processed by the EINIT
//! leaf function to verify that the enclave was properly built.

use super::{attr::Attributes, isv, misc::MiscSelect};

use core::fmt::Debug;
use core::ops::{BitAnd, BitOr, Not};

#[cfg(feature = "crypto")]
use openssl::{bn, pkey, rsa};

#[cfg(feature = "crypto")]
use core::convert::{TryFrom, TryInto};

/// Succinctly describes a masked type, e.g. masked Attributes or masked MiscSelect.
/// A mask is applied to Attributes and MiscSelect structs in a Signature (SIGSTRUCT)
/// to specify values of Attributes and MiscSelect to enforce. This struct combines
/// the struct and its mask for simplicity.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Masked<T: BitAnd<Output = T>> {
    /// The data being masked, e.g. Attribute flags.
    pub data: T,

    /// The mask.
    pub mask: T,
}

impl<T> Default for Masked<T>
where
    T: BitAnd<Output = T>,
    T: BitOr<Output = T>,
    T: Not<Output = T>,
    T: Default,
    T: Copy,
{
    fn default() -> Self {
        T::default().into()
    }
}

impl<T> From<T> for Masked<T>
where
    T: BitAnd<Output = T>,
    T: BitOr<Output = T>,
    T: Not<Output = T>,
    T: Copy,
{
    fn from(value: T) -> Self {
        Self {
            data: value,
            mask: value | !value,
        }
    }
}

impl<T> PartialEq<T> for Masked<T>
where
    T: BitAnd<Output = T>,
    T: PartialEq,
    T: Copy,
{
    fn eq(&self, other: &T) -> bool {
        self.mask & self.data == self.mask & *other
    }
}

/// The `Author` of an enclave
///
/// This structure encompasses the first block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Author {
    /// Constant byte string.
    header1: u128,
    /// Vendor.
    pub vendor: u32,
    /// YYYYMMDD in BCD.
    pub date: u32,
    /// Constant byte string.
    header2: u128,
    /// Software-defined value.
    pub swdefined: u32,
    reserved: [u32; 21],
}

impl Author {
    #[allow(clippy::unreadable_literal)]
    /// Creates a new Author from a date and software defined value.
    pub const fn new(date: u32, swdefined: u32) -> Self {
        Self {
            header1: u128::from_be(0x06000000E10000000000010000000000),
            vendor: 0u32,
            date,
            header2: u128::from_be(0x01010000600000006000000001000000),
            swdefined,
            reserved: [0; 21],
        }
    }
}

/// The enclave parameters
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Parameters {
    /// Bit vector specifying extended SSA frame feature set to be used.
    pub misc: Masked<MiscSelect>,

    /// Enclave attributes struct.
    pub attr: Masked<Attributes>,

    /// User-defined value used in key derivation.
    pub isv_prod_id: isv::ProdId,

    /// User-defined value used in key derivation.
    pub isv_svn: isv::Svn,
}

impl Parameters {
    /// Combines the parameters and a hash of the enclave to produce a `Measurement`
    pub const fn measurement(&self, mrenclave: [u8; 32]) -> Measurement {
        Measurement {
            misc: self.misc,
            reserved0: [0; 20],
            attr: self.attr,
            mrenclave,
            reserved1: [0; 32],
            isv_prod_id: self.isv_prod_id,
            isv_svn: self.isv_svn,
        }
    }
}

/// The enclave Measurement
///
/// This structure encompasses the second block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    misc: Masked<MiscSelect>,
    reserved0: [u8; 20],
    attr: Masked<Attributes>,
    mrenclave: [u8; 32],
    reserved1: [u8; 32],
    isv_prod_id: isv::ProdId,
    isv_svn: isv::Svn,
}

impl Measurement {
    /// Get the enclave measurement hash
    pub fn mrenclave(&self) -> [u8; 32] {
        self.mrenclave
    }

    /// Get the enclave parameters
    pub fn parameters(&self) -> Parameters {
        Parameters {
            isv_prod_id: self.isv_prod_id,
            isv_svn: self.isv_svn,
            misc: self.misc,
            attr: self.attr,
        }
    }

    /// Signs a measurement using the specified key on behalf of an author
    #[cfg(feature = "crypto")]
    pub fn sign(self, author: Author, key: rsa::Rsa<pkey::Private>) -> std::io::Result<Signature> {
        use openssl::{hash, sign};
        const EXPONENT: u32 = 3;

        if key.e() != &*bn::BigNum::from_u32(EXPONENT)? {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }

        let a = unsafe {
            core::slice::from_raw_parts(
                &author as *const _ as *const u8,
                core::mem::size_of_val(&author),
            )
        };

        let c = unsafe {
            core::slice::from_raw_parts(
                &self as *const _ as *const u8,
                core::mem::size_of_val(&self),
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
        let s = bn::BigNum::from_slice(&signature)?;
        let m = key.n();

        let mut ctx = bn::BigNumContext::new()?;
        let mut q1 = bn::BigNum::new()?;
        let mut qr = bn::BigNum::new()?;

        q1.div_rem(&mut qr, &(&s * &s), m, &mut ctx)?;
        let q2 = &(&s * &qr) / m;

        Ok(Signature {
            author,
            modulus: m.try_into()?,
            exponent: EXPONENT,
            signature: s.try_into()?,
            measurement: self,
            reserved: [0; 12],
            q1: q1.try_into()?,
            q2: q2.try_into()?,
        })
    }
}

#[derive(Clone)]
struct RsaNumber([u8; Self::SIZE]);

impl RsaNumber {
    const SIZE: usize = 384;
}

impl core::fmt::Debug for RsaNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02x}", *b)?;
        }

        Ok(())
    }
}

impl Eq for RsaNumber {}
impl PartialEq for RsaNumber {
    fn eq(&self, rhs: &Self) -> bool {
        self.0[..] == rhs.0[..]
    }
}

#[cfg(feature = "crypto")]
impl TryFrom<&bn::BigNumRef> for RsaNumber {
    type Error = std::io::Error;

    #[inline]
    fn try_from(value: &bn::BigNumRef) -> Result<Self, Self::Error> {
        let mut le = [0u8; Self::SIZE];
        let be = value.to_vec();

        if be.len() > Self::SIZE {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }

        for i in 0..be.len() {
            le[be.len() - i - 1] = be[i];
        }

        Ok(Self(le))
    }
}

#[cfg(feature = "crypto")]
impl TryFrom<bn::BigNum> for RsaNumber {
    type Error = std::io::Error;

    #[inline]
    fn try_from(value: bn::BigNum) -> Result<Self, Self::Error> {
        TryFrom::<&bn::BigNumRef>::try_from(&*value)
    }
}

/// The `Signature` on the enclave
///
/// This structure encompasses the `SIGSTRUCT` structure from the SGX
/// documentation, renamed for ergonomics. The two portions of the
/// data that are included in the signature are further divided into
/// subordinate structures (`Author` and `Contents`) for ease during
/// signature generation and validation.
///
/// Section 38.13
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    author: Author,
    modulus: RsaNumber,
    exponent: u32,
    signature: RsaNumber,
    measurement: Measurement,
    reserved: [u8; 12],
    q1: RsaNumber,
    q2: RsaNumber,
}

impl Signature {
    /// Get the enclave author
    pub fn author(&self) -> Author {
        self.author
    }

    /// Get the enclave measurement
    pub fn measurement(&self) -> Measurement {
        self.measurement
    }
}

#[cfg(test)]
testaso! {
    struct Author: 8, 128 => {
        header1: 0,
        vendor: 16,
        date: 20,
        header2: 24,
        swdefined: 40,
        reserved: 44
    }

    struct Measurement: 4, 128 => {
        misc: 0,
        reserved0: 8,
        attr: 28,
        mrenclave: 60,
        reserved1: 92,
        isv_prod_id: 124,
        isv_svn: 126
    }

    struct Signature: 8, 1808 => {
        author: 0,
        modulus: 128,
        exponent: 512,
        signature: 516,
        measurement: 900,
        reserved: 1028,
        q1: 1040,
        q2: 1424
    }
}

#[cfg(test)]
mod author {
    use super::Author;

    #[test]
    fn author_instantiation() {
        let author = Author::new(20000330, 0u32);
        assert_eq!(
            author.header1,
            u128::from_be(0x06000000E10000000000010000000000)
        );
        assert_eq!(author.vendor, 0u32);
        assert_eq!(
            author.header2,
            u128::from_be(0x01010000600000006000000001000000)
        );
        assert_eq!(author.swdefined, 0u32);
        assert_eq!(author.reserved, [0; 21]);
    }
}

#[cfg(all(test, feature = "crypto"))]
mod crypto {
    use super::*;

    use crate::types::page::{Flags as Perms, SecInfo};

    use primordial::Page;

    use std::fs::File;
    use std::io::Read;

    fn load(path: &str) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        let size = file.metadata().unwrap().len();

        let mut data = vec![0u8; size as usize];
        file.read_exact(&mut data).unwrap();

        data
    }

    fn loadsig(path: &str) -> Signature {
        let mut sig: Signature;
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

        let len = (bin.len() - 1) / Page::size();

        let mut tcs = [Page::default()];
        let mut src = vec![Page::default(); len];

        let dst = unsafe { tcs.align_to_mut::<u8>().1 };
        dst.copy_from_slice(&bin[..Page::size()]);

        let dst = unsafe { src.align_to_mut::<u8>().1 };
        dst.copy_from_slice(&bin[Page::size()..]);

        // Validate the hash.
        assert_eq!(
            sig.measurement().mrenclave(),
            crate::crypto::test::hash(&[
                (&tcs, SecInfo::tcs()),
                (&src, SecInfo::reg(Perms::R | Perms::W | Perms::X))
            ]),
            "failed to produce correct mrenclave hash"
        );

        // Ensure that sign() can reproduce the exact same signature struct.
        assert_eq!(
            sig,
            sig.measurement().sign(sig.author(), key).unwrap(),
            "failed to produce correct signature"
        );
    }
}
