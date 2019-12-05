//! Section 38.11

use bitflags::bitflags;

#[repr(C, align(64))]
pub struct SecInfo {
    flags: Flags,
    ptype: PageType,
    reserved: [u8; 62],
}

bitflags! {
    pub struct Flags: u8 {
        const R = 1 << 0;
        const W = 1 << 1;
        const X = 1 << 2;
        const PENDING = 1 << 2;
        const MODIFIED = 1 << 2;
        const PR = 1 << 2;
    }
}

#[repr(u8)]
pub enum PageType {
    Secs = 0,
    Tcs = 1,
    Reg = 2,
    Va = 3,
    Trim = 4,
}

impl SecInfo {
    pub fn new(flags: Flags, ptype: PageType) -> Self {
        Self {
            flags,
            ptype,
            reserved: [0u8; 62],
        }
    }
}
