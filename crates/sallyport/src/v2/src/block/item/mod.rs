// SPDX-License-Identifier: Apache-2.0

pub mod syscall;

#[allow(clippy::enum_clike_unportable_variant)]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(usize)]
pub enum Kind {
    /// Composite types. 
    // TODO: Define
    //Batch = 0x01,

    /// Terminal types.
    Syscall = 0x01 << (usize::BITS - 8),
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Header {
    pub len: usize,
    pub kind: Kind,
}
