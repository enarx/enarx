//! Section 38.11

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
        const PENDING = 1 << 2;
        const MODIFIED = 1 << 2;
        const PR = 1 << 2;
    }
}

defflags!(Flags);

/// The `Class` of a page
///
/// The `Class` type is the `PAGE_TYPE` data structure, merely renamed
/// due to the collision with the Rust `type` keyword.
///
/// Section 38.11.2
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum Class {
    Secs = 0,
    Tcs = 1,
    Reg = 2,
    Va = 3,
    Trim = 4,
}

defenum!(Class::Reg);

/// The security information (`SecInfo`) about a page
///
/// Note that the `FLAGS` field from the SGX documentation is here
/// divided into two fields (`flags` and `class`) for easy manipulation.
///
/// Section 38.11
#[derive(Copy, Clone, Default)]
#[repr(C, align(64))]
pub struct SecInfo {
    flags: Flags,
    class: Class,
}

testaso! {
    struct SecInfo: 64, 64 => {
        flags: 0,
        class: 1
    }
}

impl SecInfo {
    pub fn new(flags: Flags, class: Class) -> Self {
        Self { flags, class }
    }
}
