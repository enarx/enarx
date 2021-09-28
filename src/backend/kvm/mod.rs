// SPDX-License-Identifier: Apache-2.0

use super::Loader;
use crate::backend::kvm::data::{dev_kvm, kvm_version};
use crate::backend::kvm::mem::Region;
use anyhow::Result;
use kvm_bindings::bindings::kvm_userspace_memory_region;
pub use kvm_bindings::kvm_userspace_memory_region as KvmUserspaceMemoryRegion;
use kvm_ioctls::Kvm;
use kvm_ioctls::{VcpuFd, VmFd};
use mmarinus::{perms, Map};
use std::sync::Arc;
use x86_64::VirtAddr;

mod builder;
mod config;
mod data;
mod mem;
mod thread;

impl Keep {
    pub fn map(&mut self, pages: Map<perms::ReadWrite>, to: usize) -> std::io::Result<&mut Region> {
        let region = kvm_userspace_memory_region {
            slot: self.regions.len() as u32,
            flags: 0,
            guest_phys_addr: to as u64,
            memory_size: pages.len() as u64,
            userspace_addr: pages.addr() as u64,
        };

        unsafe { self.vm_fd.set_user_memory_region(region)? };

        self.regions.push(Region::new(region, pages));
        Ok(self.regions.last_mut().unwrap())
    }
}

struct Keep {
    kvm_fd: Kvm,
    vm_fd: VmFd,
    cpu_fds: Vec<VcpuFd>,
    // FIXME: This will be removed in the near future
    sallyport_start: VirtAddr,
    sallyports: Vec<Option<VirtAddr>>,
    regions: Vec<Region>,
}

pub struct Backend;

impl crate::backend::Backend for Backend {
    #[inline]
    fn name(&self) -> &'static str {
        "kvm"
    }

    #[inline]
    fn shim(&self) -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-sev"))
    }

    #[inline]
    fn have(&self) -> bool {
        data::dev_kvm().pass
    }

    fn data(&self) -> Vec<super::Datum> {
        vec![dev_kvm(), kvm_version()]
    }

    #[inline]
    fn keep(&self, shim: &[u8], exec: &[u8]) -> Result<Arc<dyn super::Keep>> {
        builder::Builder::load(shim, exec)
    }

    #[inline]
    fn hash(&self, _shim: &[u8], _exec: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
