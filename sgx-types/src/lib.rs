// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![no_std]
#![deny(clippy::all)]
#![allow(clippy::identity_op)]
#![deny(missing_docs)]

macro_rules! defflags {
    ($name:ident $($value:ident)|*) => {
        impl Default for $name {
            fn default() -> Self {
                $name::empty() $( | $name::$value )* | $name::empty()
            }
        }
    };
}

pub mod attr;
pub mod isv;
pub mod misc;
pub mod page;
pub mod secs;
pub mod sig;
pub mod ssa;
pub mod tcs;
pub mod ti;

use core::fmt::Debug;
use core::ops::BitAnd;

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
