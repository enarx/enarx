// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![cfg_attr(feature = "asm", feature(asm))]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::all)]
#![allow(clippy::identity_op)]
#![deny(missing_docs)]

/// This macro enables writing tests for alignment, size, and offset of fields in structs.
/// Example usage:
/// testaso! {
///     struct mystruct: 8, 4096 => {
///         f1: 0,
///         f2: 8
///     }
/// }
#[cfg(test)]
#[macro_use]
macro_rules! testaso {
    (@off $name:path=>$field:ident) => {
        memoffset::offset_of!($name, $field)
    };

    ($(struct $name:path: $align:expr, $size:expr => { $($field:ident: $offset:expr),* })+) => {
        #[cfg(test)]
        #[test]
        fn align() {
            use core::mem::align_of;

            $(
                assert_eq!(
                    align_of::<$name>(),
                    $align,
                    "align: {}",
                    stringify!($name)
                );
            )+
        }

        #[cfg(test)]
        #[test]
        fn size() {
            use core::mem::size_of;

            $(
                assert_eq!(
                    size_of::<$name>(),
                    $size,
                    "size: {}",
                    stringify!($name)
                );
            )+
        }

        #[cfg(test)]
        #[test]
        fn offsets() {
            $(
                $(
                    assert_eq!(
                        testaso!(@off $name=>$field),
                        $offset,
                        "offset: {}::{}",
                        stringify!($name),
                        stringify!($field)
                    );
                )*
        )+
        }
    };
}

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "std")]
pub mod attestation_types;
#[cfg(feature = "std")]
pub mod enclave;

pub mod types;
