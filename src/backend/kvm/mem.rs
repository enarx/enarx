// SPDX-License-Identifier: Apache-2.0

use super::KvmUserspaceMemoryRegion;

use lset::Span;
use mmarinus::{perms, Map};
use x86_64::{PhysAddr, VirtAddr};

pub struct Region {
    kvm_region: KvmUserspaceMemoryRegion,
    backing: Map<perms::ReadWrite>,
}

impl Region {
    pub fn new(kvm_region: KvmUserspaceMemoryRegion, backing: Map<perms::ReadWrite>) -> Self {
        Self {
            kvm_region,
            backing,
        }
    }

    #[allow(dead_code)]
    pub fn as_guest(&self) -> Span<PhysAddr, u64> {
        Span {
            start: PhysAddr::new(self.kvm_region.guest_phys_addr),
            count: self.kvm_region.memory_size,
        }
    }

    pub fn as_virt(&self) -> Span<VirtAddr, u64> {
        Span {
            start: VirtAddr::new(self.kvm_region.userspace_addr),
            count: self.kvm_region.memory_size,
        }
    }

    pub fn backing(&self) -> &[u8] {
        self.backing.as_ref()
    }
}
