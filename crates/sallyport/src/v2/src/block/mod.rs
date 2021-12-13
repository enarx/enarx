// SPDX-License-Identifier: Apache-2.0

//! Block-specific functionality shared between guest and host.

pub mod item;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(C)]
pub struct Header {
    _version: usize,
}
