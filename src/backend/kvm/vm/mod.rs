// SPDX-License-Identifier: Apache-2.0

pub mod builder;
mod cpu;
pub mod measure;
mod mem;
pub mod personality;

use crate::backend::{Keep, Thread};

use cpu::Cpu;
use mem::Region;
use personality::Personality;

pub use builder::{Builder, Hook};
pub use kvm_bindings::kvm_segment as KvmSegment;
pub use kvm_bindings::kvm_userspace_memory_region as KvmUserspaceMemoryRegion;

use anyhow::Result;
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VmFd};
use lset::Span;
use mmarinus::{perms, Kind, Map};
use primordial::Page;

#[cfg(target_arch = "x86_64")]
use x86_64::VirtAddr;

use std::collections::VecDeque;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

pub struct Vm<P: Personality> {
    kvm: Kvm,
    fd: VmFd,
    regions: Vec<Region>,
    syscall_blocks: Span<VirtAddr, NonZeroUsize>,
    _personality: PhantomData<P>,
    cpus: VecDeque<u64>,
}

impl<P: Personality> Vm<P> {
    pub fn add_memory(&mut self, pages: usize) -> Result<i64> {
        let mem_size = pages * Page::size();
        let last_region = self.regions.last().unwrap().as_guest();

        let map = Map::map(mem_size as usize)
            .anywhere()
            .anonymously()
            .known::<perms::ReadWrite>(Kind::Private)?;

        let region_start = map.addr();
        let region = KvmUserspaceMemoryRegion {
            slot: self.regions.len() as _,
            flags: 0,
            guest_phys_addr: last_region.start.as_u64() + last_region.count,
            memory_size: mem_size as _,
            userspace_addr: region_start as _,
        };

        unsafe {
            self.fd.set_user_memory_region(region)?;
        }

        P::add_memory(&mut self.fd, &region);

        self.regions.push(Region::new(region, map));

        Ok(region_start as _)
    }
}

impl<P: 'static + Personality> Keep for RwLock<Vm<P>> {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn Thread>>> {
        let mut keep = self.write().unwrap();

        let vcpu = match keep.cpus.pop_front() {
            Some(id) => keep.fd.create_vcpu(id)?,
            None => return Ok(None),
        };

        vcpu.set_cpuid2(&keep.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?)?;

        let thread = Cpu::new(vcpu, self.clone())?;
        Ok(Some(Box::new(thread)))
    }
}
