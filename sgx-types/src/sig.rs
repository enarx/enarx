use super::{attr::Attributes, misc::MiscSelect, utils::Padding};

// This is an internal utility type for wrapping RSA numbers.
// We use it to implement common traits. The size of the RSA
// number is determined by SGX (384 bytes).
#[derive(Copy, Clone)]
struct RsaNumber([u8; 384]);

impl core::fmt::Debug for RsaNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RsaNumber({:?})", &self.0[..])
    }
}

impl Eq for RsaNumber {}
impl PartialEq for RsaNumber {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Header1([u8; 16]);

impl Default for Header1 {
    fn default() -> Self {
        Header1([
            0x06, 0x00, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ])
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Header2([u8; 16]);

impl Default for Header2 {
    fn default() -> Self {
        Header2([
            0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00,
        ])
    }
}

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
    header1: Header1, // constant byte string
    vendor: Vendor,
    date: u32,        // YYYYMMDD in BCD
    header2: Header2, // constant byte string
    swdefined: u32,   // software defined value
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
            header1: Header1::default(),
            vendor,
            date,
            header2: Header2::default(),
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    author: Author,               // defines author of enclave
    modulus: RsaNumber,           // modulus of the pubkey (keylength=3072 bits)
    exponent: u32,                // exponent of the pubkey (RSA Exponent = 3)
    signature: RsaNumber,         // signature calculated over the fields except modulus
    contents: Contents,           // defines contents of enclave
    reserved4: Padding<[u8; 12]>, // padding
    q1: RsaNumber,                // value used in RSA signature verification
    q2: RsaNumber,                // value used in RSA signature verification
}

impl Signature {
    pub fn author(&self) -> &Author {
        &self.author
    }

    pub fn contents(&self) -> &Contents {
        &self.contents
    }
}

#[cfg(feature = "openssl")]
impl Signature {
    fn bn_to_rsanum_inner(bn: openssl::bn::BigNum) -> std::io::Result<[u8; 384]> {
        use std::io::{Error, ErrorKind};

        let bn = bn.to_vec();
        if bn.len() != 384 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Could not convert BigNum to [u8; 384]",
            ));
        }

        let mut array = [0u8; 384];
        array.copy_from_slice(&bn);
        array.reverse();
        Ok(array)
    }

    fn bn_to_u32(bn: &openssl::bn::BigNum) -> std::io::Result<u32> {
        use std::io::{Error, ErrorKind};

        let mut bn = bn.to_vec();
        while bn.len() < 4 {
            bn.push(0);
        }
        if bn.len() != 4 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Could not convert BigNum to u32",
            ));
        }

        let mut array = u32::default().to_ne_bytes(); // Zero
        array.copy_from_slice(&bn);
        array.reverse();
        Ok(u32::from_be_bytes(array))
    }

    pub fn sign(
        author: Author,
        contents: Contents,
        key: openssl::rsa::Rsa<openssl::pkey::Private>,
    ) -> std::io::Result<Self> {
        use openssl::{bn, hash, pkey, sign};

        // Generates signature on Signature author and contents
        let rsa_key = pkey::PKey::from_rsa(key.clone())?;
        let md = hash::MessageDigest::sha256();
        let mut signer = sign::Signer::new(md, &rsa_key)?;
        signer.update(author.as_ref())?;
        signer.update(contents.as_ref())?;
        let signature = signer.sign_to_vec()?;

        // Generates q1, q2 values for RSA signature verification
        let s = bn::BigNum::from_slice(&signature)?;
        let e = Self::bn_to_u32(&bn::BigNum::from_slice(&key.e().to_vec())?)?;
        let m = key.n();

        let mut ctx = bn::BigNumContext::new()?;
        let mut q1 = bn::BigNum::new()?;
        let mut qr = bn::BigNum::new()?;

        q1.div_rem(&mut qr, &(&s * &s), &m, &mut ctx)?;
        let q2 = &(&s * &qr) / m;

        // Returns modulus, signature, q1, and q2 as [u8; 384]
        let m = Self::bn_to_rsanum_inner(bn::BigNum::from_slice(&m.to_vec())?)?;
        let s = Self::bn_to_rsanum_inner(s)?;
        let q1 = Self::bn_to_rsanum_inner(q1)?;
        let q2 = Self::bn_to_rsanum_inner(q2)?;

        Ok(Self {
            author,
            modulus: RsaNumber(m),
            exponent: e,
            signature: RsaNumber(s),
            contents,
            reserved4: Padding::default(),
            q1: RsaNumber(q1),
            q2: RsaNumber(q2),
        })
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

    struct Signature: 4, 1808 => {
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

#[cfg(all(test, feature = "openssl"))]
mod test {
    use crate::{sig, test::*};
    use openssl::{pkey, rsa};

    fn load_key(path: &str) -> rsa::Rsa<pkey::Private> {
        let pem = load_bin(path);
        rsa::Rsa::private_key_from_pem(&pem).unwrap()
    }

    #[test]
    fn selftest() {
        let sig = load_sig("tests/encl.ss");
        let key = load_key("tests/encl.pem");

        let author = sig.author().clone();
        let contents = sig.contents().clone();

        // Ensure that sign() can reproduce the exact same signature struct.
        assert_eq!(
            sig,
            sig::Signature::sign(author, contents, key).unwrap(),
            "failed to produce correct signature"
        );
    }
}
