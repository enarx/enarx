// SPDX-License-Identifier: Apache-2.0

//! Modularized components for creating the initial state of VM-based keeps.

use crate::binary::Component;

pub mod x86;

/// The `Arch` trait enables architecture-specific setup for the initial
/// image.
///
/// For example, an X86_64 implementation of this could be a struct
/// that places and configures page tables.
pub trait Arch {
    fn new(_shim: &Component) -> Self;
}
