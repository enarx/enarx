// SPDX-License-Identifier: Apache-2.0

//! Intel Documentation related to these types is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf

#![no_std]
#![deny(clippy::all)]
#![allow(clippy::identity_op)]
#![deny(missing_docs)]

use core::{fmt::Debug, ops::BitAnd};

/// Succinctly describes a masked type, e.g. masked Attributes or masked MiscSelect.
/// A mask is applied to Attributes and MiscSelect structs in a Signature (SIGSTRUCT)
/// to specify values of Attributes and MiscSelect to enforce. This struct combines
/// the struct and its mask for simplicity.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Masked<T: Copy + Debug + PartialEq + BitAnd<Output = T>> {
    /// The data being masked, e.g. Attribute flags.
    pub data: T,

    /// The mask.
    pub mask: T,
}

impl<T: Copy + Debug + PartialEq + BitAnd<Output = T>> From<T> for Masked<T> {
    fn from(value: T) -> Self {
        Self {
            data: value,
            mask: value,
        }
    }
}

impl<T: Copy + Debug + PartialEq + BitAnd<Output = T>> PartialEq<T> for Masked<T> {
    fn eq(&self, other: &T) -> bool {
        self.mask & self.data == self.mask & *other
    }
}

/// The size of XSAVE region in SSA is derived from the enclave’s support of the collection
/// of processor extended states that would be managed by XSAVE. The enablement of those
/// processor extended state components in conjunction with CPUID leaf 0DH information
/// determines the XSAVE region size in SSA.
///
/// Section 38.9, Table 38-7
#[derive(Debug)]
#[repr(C, align(4096))]
pub struct XSave([[u64; 32]; 16]);
