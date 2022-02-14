// SPDX-License-Identifier: Apache-2.0

//! Page SecInfo (Section 38.11)
//! These structs specify metadata about en enclave page.

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

        /// The page is in the PENDING state.
        const PENDING = 1 << 3;

        /// The page is in the MODIFIED state.
        const MODIFIED = 1 << 4;

        /// A permission restriction operation on the page is in progress.
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
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Class {
    /// Page is an SECS.
    Secs = 0,
    /// Page is a TCS.
    Tcs = 1,
    /// Page is a regular page.
    Reg = 2,
    /// Page is a Version Array.
    Va = 3,
    /// Page is in trimmed state.
    Trim = 4,
}

/// The security information (`SecInfo`) about a page
///
/// Note that the `FLAGS` field from the SGX documentation is here
/// divided into two fields (`flags` and `class`) for easy manipulation.
///
/// Section 38.11
#[derive(Copy, Clone)]
#[repr(C, align(64))]
pub struct SecInfo {
    /// Section 38.11.1
    pub flags: Flags,
    /// Section 38.11.2
    pub class: Class,
    reserved: [u16; 31],
}

impl core::fmt::Debug for SecInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecInfo")
            .field("class", &self.class)
            .field("flags", &self.flags)
            .finish()
    }
}

impl SecInfo {
    /// Creates a SecInfo (page) of class type Regular.
    pub const fn reg(flags: Flags) -> Self {
        Self {
            flags,
            class: Class::Reg,
            reserved: [0; 31],
        }
    }

    /// Creates a SecInfo (page) of class type TCS.
    pub const fn tcs() -> Self {
        Self {
            flags: Flags::empty(),
            class: Class::Tcs,
            reserved: [0; 31],
        }
    }
}

#[cfg(test)]
testaso! {
    struct SecInfo: 64, 64 => {
        flags: 0,
        class: 1
    }
}
