// SPDX-License-Identifier: Apache-2.0

use crate::backend::kvm::Personality;
use kvm_ioctls::VmFd;

use super::ioctl::KvmUserspaceMemoryRegion;
use super::runtime::mark_encrypted;

pub struct Sev;

impl Personality for Sev {
    fn add_memory(vm: &VmFd, region: &KvmUserspaceMemoryRegion) {
        mark_encrypted(vm, region).expect("SEV memory pinning failed");
    }
}
