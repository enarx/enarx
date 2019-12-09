// Copyright 2019 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![deny(clippy::all)]
#![allow(clippy::identity_op)]

macro_rules! defenum {
    ($name:ident::$value:ident) => {
        impl Default for $name {
            fn default() -> Self {
                $name::$value
            }
        }
    };
}

macro_rules! defflags {
    ($name:ident $($value:ident)|*) => {
        impl Default for $name {
            fn default() -> Self {
                $name::empty() $( | $name::$value )* | $name::empty()
            }
        }
    };
}

macro_rules! testaso {
    (@off $name:ident.$field:ident) => {
        &unsafe { &*core::ptr::null::<$name>() }.$field as *const _ as usize
    };

    ($(struct $name:ident: $align:expr, $size:expr => { $($field:ident: $offset:expr),* })+) => {
        #[cfg(test)]
        #[test]
        fn aso() {
            use core::mem::*;

            $(
                assert_eq!(align_of::<$name>(), $align, "align: {}", stringify!($name));
                assert_eq!(size_of::<$name>(), $size, "size: {}", stringify!($name));
                $(
                    assert_eq!(testaso!(@off $name.$field), $offset, "offset: {}::{}", stringify!($name), stringify!($field));
                )*
            )+
        }
    };
}

mod utils;

pub mod attr;
pub mod misc;
pub mod page;
pub mod secs;
pub mod sig;
pub mod ssa;
pub mod tcs;

use core::marker::PhantomData;

/// An offset reference with neither read nor write capabilities
///
/// The Offset struct allows the creation of an opaque reference to a
/// type that cannot be read or written. Neither the lifetime nor the
/// type are discarded. This allows us to refer to an offset inside
/// an enclave without fear that it will be dereferenced. The size of
/// the Offset is always 64 bits with natural alignment. Therefore,
/// the Offset type can be embedded in structs.
#[repr(transparent)]
#[derive(Debug)]
pub struct Offset<'h, T>(u64, PhantomData<&'h T>);

impl<'h, T> Offset<'h, T> {
    /// Create a new `Offset`
    ///
    /// # Safety
    ///
    /// This function is unsafe because you could create an Offset to an
    /// offset that doesn't exist. This could cause an invalid memory
    /// reference later in the program. You must ensure that both the
    /// lifetime and the offset are valid.
    pub unsafe fn new(offset: usize) -> Self {
        Offset(offset as u64, PhantomData)
    }
}
