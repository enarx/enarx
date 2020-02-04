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
