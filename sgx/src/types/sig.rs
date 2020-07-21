// SPDX-License-Identifier: Apache-2.0

//! SigStruct (Section 38.13)
//! SigStruct is a structure created and signed by the enclave developer that
//! contains information about the enclave. SIGSTRUCT is processed by the EINIT
//! leaf function to verify that the enclave was properly built.

use super::{attr::Attributes, isv, misc::MiscSelect};
use intel_types::Masked;

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
}

#[derive(Clone)]
struct RsaNumber([u8; 384]);

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
    /// Creates a new Signature.
    pub const fn new(
        author: Author,
        measurement: Measurement,
        exponent: u32,
        modulus: [u8; 384],
        signature: [u8; 384],
        q1: [u8; 384],
        q2: [u8; 384],
    ) -> Self {
        Self {
            author,
            modulus: RsaNumber(modulus),
            exponent,
            signature: RsaNumber(signature),
            measurement,
            reserved: [0; 12],
            q1: RsaNumber(q1),
            q2: RsaNumber(q2),
        }
    }

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
mod tests {
    use super::*;
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
