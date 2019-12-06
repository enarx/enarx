use super::{attributes::Attributes, miscselect::MiscSelect, xfrm::Xfrm};

const SGX_MODULUS_SIZE: usize = 384;
const SIGSTRUCT_HEADER1: [u8; 16] = [
    0x06, 0x00, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const SIGSTRUCT_HEADER2: [u8; 16] = [
    0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x000,
];

#[repr(u32)]
pub enum Vendor {
    Unknown = 0x0000,
    Intel = 0x8086,
}

/// The sgx_sigstruct_header defines the author of the enclave
#[repr(C, packed)]
pub struct SigStructHeader {
    header1: [u8; 16], // constant byte string
    vendor: Vendor,
    date: u32,         // YYYYMMDD in BCD
    header2: [u8; 16], // constant byte string
    swdefined: u32,    // software defined value
    _reserved1: [u8; 84],
}

/// The sgx_sigstruct_body defines contents of the enclave
#[repr(C, packed)]
#[derive(Default)]
pub struct SigStructBody {
    miscselect: MiscSelect,      // bit vector specifying extended SSA frame feature set to be used
    misc_mask: MiscSelect,       // required miscselect in SECS; bit vector mask of MISCSELECT to enforce
    _reserved2: [u8; 20],
    attributes: Attributes,      // attributes for enclave
    xfrm: Xfrm,                  // xsave feature request mask (subset of xcr0)
    attributes_mask: Attributes, // required attributes in SECS; mask of attributes to enforce
    xfrm_mask: Xfrm,              // required xfrm in SECS
    mrenclave: [u8; 32],         // sha256 hash of enclave contents
    _reserved3: [u8; 32],
    isvprodid: u16,              // user-defined value used in key derivation
    isvsvn: u16,                 // user-defined value used in key derivation
}

/// SigStructHeader and SigStructbody are signed. The remaining fields
/// define the signature of the enclave.
#[repr(C, packed)]
pub struct SigStruct {
    header: SigStructHeader,         // defines author of enclave
    modulus: [u8; SGX_MODULUS_SIZE], // modulus of the pubkey (keylength=3072 bits)
    exponent: u32,                   // exponent of the pubkey (RSA Exponent = 3)
    signature: [u8; 384],            // signature calculated over the fields except modulus
    body: SigStructBody,             // defines contents of enclave
    _reserved4: [u8; 12],
    q1: [u8; 384], // value used in RSA signature verification
    q2: [u8; 384], // value used in RSA signature verification
}

impl Default for SigStructHeader {
    fn default() -> Self {
        SigStructHeader {
            header1: SIGSTRUCT_HEADER1,
            vendor: Vendor::Intel,
            date: u32::default(),
            header2: SIGSTRUCT_HEADER2,
            swdefined: u32::default(),
            _reserved1: [0u8; 84],
        }
    }
}

impl Default for SigStruct {
    fn default() -> Self {
        SigStruct {
            header: SigStructHeader::default(),
            modulus: [0u8; SGX_MODULUS_SIZE],
            exponent: 3u32,
            signature: [0u8; SGX_MODULUS_SIZE],
            body: SigStructBody::default(),
            _reserved4: [0u8; 12],
            q1: [0u8; SGX_MODULUS_SIZE],
            q2: [0u8; SGX_MODULUS_SIZE],
        }
    }
}
