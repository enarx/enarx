// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![allow(clippy::module_inception)]
#![cfg(feature = "crypto")]
#![cfg(feature = "std")]
#![cfg(feature = "asm")]

mod builder;
mod enclave;
mod ioctls;

pub use builder::*;
pub use enclave::*;
