// SPDX-License-Identifier: Apache-2.0

pub use kvm_bindings::kvm_userspace_memory_region as KvmUserspaceMemoryRegion;
use mmap::Unmap;
use span::Span;
use x86_64::VirtAddr;

pub struct Region {
    kvm_region: KvmUserspaceMemoryRegion,
    _backing: Unmap,
}

impl Region {
    pub fn new(kvm_region: KvmUserspaceMemoryRegion, backing: Unmap) -> Self {
        Self {
            kvm_region,
            _backing: backing,
        }
    }

    pub fn as_virt(&self) -> Span<VirtAddr, u64> {
        Span {
            start: VirtAddr::new(self.kvm_region.userspace_addr),
            count: self.kvm_region.memory_size,
        }
    }
}
