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

#![no_std]
#![deny(clippy::all)]
#![allow(clippy::identity_op)]

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
    (@off $name:ty=>$field:ident) => {
        &unsafe { &*core::ptr::null::<$name>() }.$field as *const _ as usize
    };

    ($(struct $name:ty: $align:expr, $size:expr => { $($field:ident: $offset:expr),* })+) => {
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

pub mod attr;
pub mod misc;
pub mod page;
pub mod secs;
pub mod sig;
pub mod ssa;
pub mod tcs;

use core::fmt::Debug;
use core::ops::BitAnd;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Masked<T: Copy + Debug + PartialEq + BitAnd<Output = T>> {
    pub data: T,
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
