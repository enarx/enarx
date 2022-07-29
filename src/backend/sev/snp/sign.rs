// SPDX-License-Identifier: Apache-2.0

use crate::backend::ByteSized;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Es384 {
    pub r: [u8; 0x48],
    pub s: [u8; 0x48],
}

impl Default for Es384 {
    fn default() -> Self {
        Self {
            r: [0u8; 0x48],
            s: [0u8; 0x48],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub component: Es384,
    rsvd: [u8; 368], // must be zero as per SEV-SNP firmware ABI
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            component: Es384::default(),
            rsvd: [0u8; 368],
        }
    }
}

// SAFETY: Signature is a C struct with no UD states and pointers.
unsafe impl ByteSized for Signature {}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub curve: u32,
    pub component: Es384,
    rsvd: [u8; 880], // must be zero as per SEV-SNP firmware ABI
}

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            curve: 2,
            component: Es384::default(),
            rsvd: [0u8; 880],
        }
    }
}

// SAFETY: PublicKey is a C struct with no UD states and pointers.
unsafe impl ByteSized for PublicKey {}
