// SPDX-License-Identifier: Apache-2.0

//! Architecture-specific setup for x86_64 VMs.

use super::Arch;
use crate::binary::{Component, PT_ENARX_PML4};
use x86_64::PhysAddr;

/// The x86_64 shim.
pub struct X86 {
    pub rip: PhysAddr,
    pub cr3: PhysAddr,
}

impl Arch for X86 {
    fn new(shim: &Component) -> Self {
        X86 {
            rip: PhysAddr::new(shim.elf.entry as _),
            cr3: PhysAddr::new(shim.find_header(PT_ENARX_PML4).unwrap().vm_range().start as _),
        }
    }
}
