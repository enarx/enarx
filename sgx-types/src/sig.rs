use super::{attr::Attributes, misc::MiscSelect, utils::Padding};

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct RsaNumber([u8; 384]);

impl Default for RsaNumber {
    fn default() -> Self {
        RsaNumber([0u8; 384])
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct RsaExponent(u32);

impl Default for RsaExponent {
    fn default() -> Self {
        Self(65537)
    }
}

#[derive(Copy, Clone)]
struct Header1([u8; 16]);

impl Default for Header1 {
    fn default() -> Self {
        Header1([
            0x06, 0x00, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ])
    }
}

#[derive(Copy, Clone)]
struct Header2([u8; 16]);

impl Default for Header2 {
    fn default() -> Self {
        Header2([
            0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00,
        ])
    }
}

#[derive(Copy, Clone)]
#[repr(u32)]
pub enum Vendor {
    Unknown = 0x0000,
    Intel = 0x8086,
}

defenum!(Vendor::Unknown);

/// The `Author` of an enclave
///
/// This structure encompasses the first block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Default)]
pub struct Author {
    header1: Header1, // constant byte string
    pub vendor: Vendor,
    pub date: u32,      // YYYYMMDD in BCD
    header2: Header2,   // constant byte string
    pub swdefined: u32, // software defined value
    reserved1: Padding<[u8; 84]>,
}

/// The `Contents` of an enclave
///
/// This structure encompasses the second block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Default)]
pub struct Contents {
    pub misc: MiscSelect, // bit vector specifying extended SSA frame feature set to be used
    pub misc_mask: MiscSelect, // required miscselect in SECS; bit vector mask of MISCSELECT to enforce
    reserved2: Padding<[u8; 20]>,
    pub attr: Attributes,
    pub attr_mask: Attributes,
    pub mrenclave: [u8; 32], // sha256 hash of enclave contents
    reserved3: Padding<[u8; 32]>,
    pub isv_prod_id: u16, // user-defined value used in key derivation
    pub isv_svn: u16,     // user-defined value used in key derivation
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
#[repr(C, align(4096))]
#[derive(Default)]
pub struct Signature {
    pub author: Author,        // defines author of enclave
    pub modulus: RsaNumber,    // modulus of the pubkey (keylength=3072 bits)
    pub exponent: RsaExponent, // exponent of the pubkey (RSA Exponent = 3)
    pub signature: RsaNumber,  // signature calculated over the fields except modulus
    pub contents: Contents,    // defines contents of enclave
    reserved4: Padding<[u8; 12]>,
    pub q1: RsaNumber, // value used in RSA signature verification
    pub q2: RsaNumber, // value used in RSA signature verification
}

impl Signature {
    /// Creates a signature from a mrenclave hash
    pub fn from_hash(hash: [u8; 32]) -> Self {
        let contents = Contents {
            mrenclave: hash,
            ..Default::default()
        };
        Signature {
            contents: contents,
            ..Default::default()
        }
    }
}

testaso! {
    struct Author: 4, 128 => {
        header1: 0,
        vendor: 16,
        date: 20,
        header2: 24,
        swdefined: 40,
        reserved1: 44
    }

    struct Contents: 4, 128 => {
        misc: 0,
        misc_mask: 4,
        reserved2: 8,
        attr: 28,
        attr_mask: 44,
        mrenclave: 60,
        reserved3: 92,
        isv_prod_id: 124,
        isv_svn: 126
    }

    struct Signature: 4096, 4096 => {
        author: 0,
        modulus: 128,
        exponent: 512,
        signature: 516,
        contents: 900,
        reserved4: 1028,
        q1: 1040,
        q2: 1424
    }
}
