//! Section 38.11

use crate::utils::Padding;
use bitflags::bitflags;

bitflags! {
    /// The `Flags` of a page
    ///
    /// Section 38.11.1
    pub struct Flags: u8 {
        /// The page can be read from inside the enclave.
        const R = 1 << 0;

        /// The page can be written from inside the enclave.
        const W = 1 << 1;

        /// The page can be executed from inside the enclave.
        const X = 1 << 2;

        const PENDING = 1 << 3;
        const MODIFIED = 1 << 4;
        const PR = 1 << 5;
    }
}

/// The `Class` of a page
///
/// The `Class` type is the `PAGE_TYPE` data structure, merely renamed
/// due to the collision with the Rust `type` keyword.
///
/// Section 38.11.2
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum Class {
    Secs = 0,
    Tcs = 1,
    Reg = 2,
    Va = 3,
    Trim = 4,
}

/// The security information (`SecInfo`) about a page
///
/// Note that the `FLAGS` field from the SGX documentation is here
/// divided into two fields (`flags` and `class`) for easy manipulation.
///
/// Section 38.11
#[derive(Copy, Clone, Debug)]
#[repr(C, align(64))]
pub struct SecInfo {
    flags: Flags,
    class: Class,
    reserved: Padding<[u8; 62]>,
}

impl AsRef<[u8]> for SecInfo {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of_val(self),
            )
        }
    }
}

impl SecInfo {
    pub fn reg(flags: Flags) -> Self {
        Self {
            flags,
            class: Class::Reg,
            reserved: Padding::default(),
        }
    }

    pub fn tcs() -> Self {
        Self {
            flags: Flags::empty(),
            class: Class::Tcs,
            reserved: Padding::default(),
        }
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn class(&self) -> Class {
        self.class
    }
}

testaso! {
    struct SecInfo: 64, 64 => {
        flags: 0,
        class: 1
    }
}
