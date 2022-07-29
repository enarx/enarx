// SPDX-License-Identifier: Apache-2.0

pub use kvm_bindings::kvm_userspace_memory_region as KvmUserspaceMemoryRegion;

use super::Loader;
use data::{dev_kvm, kvm_version, CPUIDS};
use mem::Region;

use std::sync::Arc;

use crate::backend::Signatures;
use anyhow::Result;
use kvm_bindings::bindings::kvm_userspace_memory_region;
use kvm_ioctls::Kvm;
use kvm_ioctls::{VcpuFd, VmFd};
use mmarinus::{perms, Map};
use sallyport::item::enarxcall::Payload;
use sallyport::item::Item;
use x86_64::VirtAddr;

pub mod builder;
pub mod config;
pub mod data;
pub mod mem;
pub mod thread;

pub trait KeepPersonality {
    fn map(_vm_fd: &mut VmFd, _region: &Region) -> std::io::Result<()> {
        Ok(())
    }

    fn enarxcall<'a>(
        &mut self,
        enarxcall: &'a mut Payload,
        data: &'a mut [u8],
    ) -> Result<Option<Item<'a>>> {
        Ok(Some(Item::Enarxcall(enarxcall, data)))
    }
}

struct KvmKeepPersonality(());

impl KeepPersonality for KvmKeepPersonality {}

pub struct Keep<P: KeepPersonality> {
    pub kvm_fd: Kvm,
    pub vm_fd: VmFd,
    pub cpu_fds: Vec<VcpuFd>,
    pub sallyport_block_size: usize,
    pub sallyports: Vec<Option<VirtAddr>>,
    pub regions: Vec<Region>,
    pub personality: P,
}

impl<P: KeepPersonality> Keep<P> {
    pub fn map(&mut self, pages: Map<perms::ReadWrite>, to: usize) -> std::io::Result<&mut Region> {
        let kvm_region = kvm_userspace_memory_region {
            slot: self.regions.len() as u32,
            flags: 0,
            guest_phys_addr: to as u64,
            memory_size: pages.len() as u64,
            userspace_addr: pages.addr() as u64,
        };

        unsafe { self.vm_fd.set_user_memory_region(kvm_region)? };

        let region = Region::new(kvm_region, pages);

        P::map(&mut self.vm_fd, &region)?;

        self.regions.push(region);

        Ok(self.regions.last_mut().unwrap())
    }
}

pub struct Backend;

impl crate::backend::Backend for Backend {
    #[inline]
    fn name(&self) -> &'static str {
        "kvm"
    }

    #[inline]
    fn shim(&self) -> &'static [u8] {
        include_bytes!(env!("CARGO_BIN_FILE_ENARX_SHIM_KVM"))
    }

    #[inline]
    fn have(&self) -> bool {
        self.data().iter().all(|x| x.pass)
    }

    fn data(&self) -> Vec<super::Datum> {
        let mut data = vec![dev_kvm(), kvm_version()];
        data.extend(CPUIDS.iter().map(|c| c.into()));
        data
    }

    fn config(&self) -> Vec<super::Datum> {
        vec![]
    }

    #[inline]
    fn keep(
        &self,
        shim: &[u8],
        exec: &[u8],
        signatures: Option<Signatures>,
    ) -> Result<Arc<dyn super::Keep>> {
        builder::Builder::load(shim, exec, signatures)
    }

    #[inline]
    fn hash(&self, _shim: &[u8], _exec: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg_attr(debug_assertions, ignore = "debug_assertions active")]
    fn shim_kvm_binary_size() {
        use crate::backend::Backend;

        let max_shim_size = 500_000;
        let shim = super::Backend.shim();
        if shim.len() > max_shim_size {
            panic!(
                "shim size should be less than {} bytes, but is {} bytes",
                max_shim_size,
                shim.len()
            );
        }
    }
}
