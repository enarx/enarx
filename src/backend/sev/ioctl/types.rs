// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

pub use kvm_bindings::kvm_userspace_memory_region as KvmUserspaceMemoryRegion;

#[repr(C)]
pub struct KvmEncRegion<'a> {
    addr: u64,
    size: u64,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> KvmEncRegion<'a> {
    pub fn new(region: &'a KvmUserspaceMemoryRegion) -> Self {
        Self {
            addr: region.userspace_addr,
            size: region.memory_size,
            _phantom: PhantomData,
        }
    }
}
