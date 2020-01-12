use super::{attr::Attributes, misc::MiscSelect, utils::Padding};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Author {
    header1: u128,  // constant byte string
    vendor: Vendor, // vendor
    date: u32,      // YYYYMMDD in BCD
    header2: u128,  // constant byte string
    swdefined: u32, // software defined value
    reserved1: Padding<[u8; 84]>,
}

impl AsRef<[u8]> for Author {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of_val(self),
            )
        }
    }
}

impl Author {
    pub fn new(vendor: Vendor, date: u32, swdefined: u32) -> Self {
        Author {
            header1: u128::from_be(0x06000000E10000000000010000000000),
            vendor,
            date,
            header2: u128::from_be(0x01010000600000006000000001000000),
            swdefined,
            reserved1: Padding::default(),
        }
    }
}

/// The `Contents` of an enclave
///
/// This structure encompasses the second block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contents {
    misc: MiscSelect, // bit vector specifying extended SSA frame feature set to be used
    misc_mask: MiscSelect, // required miscselect in SECS; bit vector mask of MISCSELECT to enforce
    reserved2: Padding<[u8; 20]>,
    attr: Attributes,
    attr_mask: Attributes,
    mrenclave: [u8; 32], // sha256 hash of enclave contents
    reserved3: Padding<[u8; 32]>,
    isv_prod_id: u16, // user-defined value used in key derivation
    isv_svn: u16,     // user-defined value used in key derivation
}

impl AsRef<[u8]> for Contents {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of_val(self),
            )
        }
    }
}

impl Contents {
    pub fn new(
        misc: MiscSelect,
        misc_mask: MiscSelect,
        attr: Attributes,
        attr_mask: Attributes,
        mrenclave: [u8; 32],
        isv_prod_id: u16,
        isv_svn: u16,
    ) -> Self {
        Self {
            misc,
            misc_mask,
            reserved2: Padding::default(),
            attr,
            attr_mask,
            mrenclave,
            reserved3: Padding::default(),
            isv_prod_id,
            isv_svn,
        }
    }

    pub fn misc(&self) -> MiscSelect {
        self.misc & self.misc_mask
    }

    pub fn attr(&self) -> Attributes {
        self.attr & self.attr_mask
    }

    pub fn mrenclave(&self) -> [u8; 32] {
        self.mrenclave
    }

    pub fn isv_prod_id(&self) -> u16 {
        self.isv_prod_id
    }

    pub fn isv_svn(&self) -> u16 {
        self.isv_svn
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
    author: Author,               // defines author of enclave
    modulus: [u8; 384],           // modulus of the pubkey (keylength=3072 bits)
    exponent: u32,                // exponent of the pubkey (RSA Exponent = 3)
    signature: [u8; 384],         // signature calculated over the fields except modulus
    contents: Contents,           // defines contents of enclave
    reserved4: Padding<[u8; 12]>, // padding
    q1: [u8; 384],                // value used in RSA signature verification
    q2: [u8; 384],                // value used in RSA signature verification
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature {{")?;
        write!(f, " author: {:?},", self.author)?;
        write!(f, " modulus: {:?},", &self.modulus[..])?;
        write!(f, " exponent: {:?},", self.exponent)?;
        write!(f, " signature: {:?},", &self.signature[..])?;
        write!(f, " contents: {:?},", self.contents)?;
        write!(f, " reserved: {:?},", self.reserved4)?;
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
            && self.reserved4 == other.reserved4
            && &self.q1[..] == &other.q1[..]
            && &self.q2[..] == &other.q2[..]
    }
}

impl Signature {
    pub fn new(
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
            reserved4: Padding::default(),
            q1,
            q2,
        }
    }

    pub fn author(&self) -> &Author {
        &self.author
    }

    pub fn modulus(&self) -> &[u8; 384] {
        &self.modulus
    }

    pub fn contents(&self) -> &Contents {
        &self.contents
    }
}

testaso! {
    struct Author: 8, 128 => {
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

    struct Signature: 8, 1808 => {
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
