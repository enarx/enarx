#[repr(u32)]
pub enum Vendor {
    Unknown = 0x0000,
    Intel = 0x8086,
}

#[repr(C, packed)]
pub struct SigStructHeader {
    header1: [u8; 16],
    vendor: Vendor,
    date: u32,
    header2: [u8; 16],
    swdefined: u32,
    _reserved1: [u8; 84],
}

#[repr(C, packed)]
pub struct SigStructBody {
    miscselect: u32,
    misc_mask: u32,
    _reserved2: [u8; 20],
    attributes: u64,
    xfrm: u64,
    attributes_mask: u64,
    xfrm_mask: u64,
    mrenclave: [u8; 32],
    _reserved3: [u8; 32],
    isvprodid: u16,
    isvsvn: u16,
}

#[repr(C, packed)]
pub struct SigStruct {
    header: SigStructHeader,
    exponent: u32,
    signature: [u8; 384],
    body: SigStructBody,
    _reserved4: [u8; 12],
    q1: [u8; 384],
    q2: [u8; 384],
}