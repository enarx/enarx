// SPDX-License-Identifier: Apache-2.0

use super::Loader;
use data::{dev_kvm, kvm_version, CPUIDS};
use mem::{Region, Slot};

use std::sync::Arc;

use crate::backend::Signatures;
use anyhow::Result;
use kvm_ioctls::Kvm;
use kvm_ioctls::{VcpuFd, VmFd};
use lset::Contains;
use mmarinus::{perms, Map};
use sallyport::item::enarxcall::Payload;
use sallyport::item::Item;
use x86_64::{PhysAddr, VirtAddr};

pub mod builder;
pub mod config;
pub mod data;
pub mod mem;
pub mod thread;

pub trait KeepPersonality: Send + Sync + 'static {
    fn map(_vm_fd: &mut VmFd, _region: &Region, _is_private: bool) -> std::io::Result<()> {
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

pub struct Keep<P: KeepPersonality + Send> {
    pub kvm_fd: Kvm,
    pub vm_fd: VmFd,
    pub num_cpus: u64,
    pub cpu_fds: Vec<VcpuFd>,
    pub sallyport_block_size: usize,
    pub sallyports: Vec<Option<VirtAddr>>,
    pub regions: Vec<Region>,
    pub personality: P,
}

impl<P: KeepPersonality> Keep<P> {
    /// Allocator for `enarxcall::BalloonMemory'.
    pub fn map(
        &mut self,
        pages: Map<perms::ReadWrite>,
        to: usize,
        is_private: bool,
    ) -> std::io::Result<&mut Region> {
        let slot = Slot::new(
            &mut self.vm_fd,
            self.regions.len() as u32,
            &pages,
            to as u64,
            is_private,
        )?;
        let region = Region::new(slot, pages);

        P::map(&mut self.vm_fd, &region, is_private)?;

        self.regions.push(region);

        Ok(self.regions.last_mut().unwrap())
    }
    pub fn virt_from_guest_phys(&self, guest_phys: PhysAddr) -> Option<VirtAddr> {
        for region in &self.regions {
            if region.as_guest().contains(&guest_phys) {
                return Some(region.as_virt().start + (guest_phys - region.as_guest().start));
            }
        }
        None
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
