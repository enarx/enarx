// SPDX-License-Identifier: Apache-2.0

//! SigStruct (Section 38.13)
//! SigStruct is a structure created and signed by the enclave developer that
//! contains information about the enclave. SIGSTRUCT is processed by the EINIT
//! leaf function to verify that the enclave was properly built.

use super::{attr::Attributes, isv, misc::MiscSelect};
use intel_types::Masked;
use testing::testaso;

/// Holds an ID that specifies the vendor of the enclave.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Vendor(u32);

impl Vendor {
    /// Vendor ID for unknown vendor.
    pub const UNKNOWN: Vendor = Vendor(0x0000);
    /// Vendor ID for Intel.
    pub const INTEL: Vendor = Vendor(0x8086);

    /// Creates a new Vendor based on vendor ID.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    #[allow(clippy::unreadable_literal)]
    /// Creates a new Author from a date and software defined value.
    pub const fn author(self, date: u32, swdefined: u32) -> Author {
        Author {
            header1: u128::from_be(0x06000000E10000000000010000000000),
            vendor: self,
            date,
            header2: u128::from_be(0x01010000600000006000000001000000),
            swdefined,
            reserved: [0; 21],
        }
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
    pub vendor: Vendor,
    /// YYYYMMDD in BCD.
    pub date: u32,
    /// Constant byte string.
    header2: u128,
    /// Software-defined value.
    pub swdefined: u32,
    reserved: [u32; 21],
}

/// The `Contents` of an enclave
///
/// This structure encompasses the second block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Contents {
    /// Bit vector specifying extended SSA frame feature set to be used.
    pub misc: Masked<MiscSelect>,
    reserved0: [u8; 20],
    /// Enclave attributes struct.
    pub attr: Masked<Attributes>,
    /// SHA256 hash of enclave contents.
    pub mrenclave: [u8; 32],
    reserved1: [u8; 32],
    /// User-defined value used in key derivation.
    pub isv_prod_id: isv::ProdId,
    /// User-defined value used in key derivation.
    pub isv_svn: isv::Svn,
}

impl Contents {
    /// Creates new SIGSTRUCT Contents from known values (including MRENCLAVE).
    pub fn new(
        misc: Masked<MiscSelect>,
        attr: Masked<Attributes>,
        mrenclave: [u8; 32],
        isv_prod_id: isv::ProdId,
        isv_svn: isv::Svn,
    ) -> Self {
        Self {
            misc,
            reserved0: [0; 20],
            attr,
            mrenclave,
            reserved1: [0; 32],
            isv_prod_id,
            isv_svn,
        }
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
#[derive(Clone)]
pub struct Signature {
    /// Defines the author of an enclave.
    pub author: Author,
    /// Modulus of the pubkey (key length = 3072 bits).
    pub modulus: [u8; 384],
    /// Exponent of the pubkey (RSA exponent = 3).
    pub exponent: u32,
    /// Signature calculated over the fields except modulus.
    pub signature: [u8; 384],
    /// Defines the contents of an enclave.
    pub contents: Contents,
    reserved: [u8; 12],
    /// Value used in RSA signature verification.
    pub q1: [u8; 384],
    /// Value used in RSA signature verification.
    pub q2: [u8; 384],
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature {{")?;
        write!(f, " author: {:?},", self.author)?;
        write!(f, " modulus: {:?},", &self.modulus[..])?;
        write!(f, " exponent: {:?},", self.exponent)?;
        write!(f, " signature: {:?},", &self.signature[..])?;
        write!(f, " contents: {:?},", self.contents)?;
        write!(f, " reserved: {:?},", self.reserved)?;
        write!(f, " q1: {:?},", &self.q1[..])?;
        write!(f, " q1: {:?} ", &self.q2[..])?;
        write!(f, "}}")
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    #[allow(clippy::op_ref)]
    fn eq(&self, other: &Self) -> bool {
        self.author == other.author
            && &self.modulus[..] == &other.modulus[..]
            && self.exponent == other.exponent
            && &self.signature[..] == &other.signature[..]
            && self.contents == other.contents
            && self.reserved == other.reserved
            && &self.q1[..] == &other.q1[..]
            && &self.q2[..] == &other.q2[..]
    }
}

impl Signature {
    /// Creates a new Signature.
    pub const fn new(
        author: Author,
        contents: Contents,
        exponent: u32,
        modulus: [u8; 384],
        signature: [u8; 384],
        q1: [u8; 384],
        q2: [u8; 384],
    ) -> Self {
        Self {
            author,
            modulus,
            exponent,
            signature,
            contents,
            reserved: [0; 12],
            q1,
            q2,
        }
    }
}

testaso! {
    struct Author: 8, 128 => {
        header1: 0,
        vendor: 16,
        date: 20,
        header2: 24,
        swdefined: 40,
        reserved: 44
    }

    struct Contents: 4, 128 => {
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
        contents: 900,
        reserved: 1028,
        q1: 1040,
        q2: 1424
    }
}
