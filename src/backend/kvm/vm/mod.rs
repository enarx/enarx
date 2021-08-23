// SPDX-License-Identifier: Apache-2.0

pub mod builder;
mod cpu;
pub mod image;
pub mod measure;
mod mem;
pub mod personality;

use crate::backend::{Keep, Thread};

use cpu::Cpu;
use mem::Region;
use personality::Personality;

pub use builder::{Builder, Hook};
pub use image::{x86::X86, Arch};
pub use kvm_bindings::kvm_segment as KvmSegment;
pub use kvm_bindings::kvm_userspace_memory_region as KvmUserspaceMemoryRegion;

use anyhow::Result;
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VmFd};
use lset::Span;
use mmarinus::{perms, Kind, Map};
use primordial::Page;
use x86_64::VirtAddr;

use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

pub struct Vm<A: Arch, P: Personality> {
    kvm: Kvm,
    fd: VmFd,
    regions: Vec<Region>,
    syscall_blocks: Span<VirtAddr, NonZeroUsize>,
    arch: A,
    _personality: PhantomData<P>,
}

impl<A: Arch, P: Personality> Vm<A, P> {
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

        P::add_memory(&self.fd, &region);

        self.regions.push(Region::new(region, map));

        Ok(region_start as _)
    }
}

impl<P: 'static + Personality> Keep for RwLock<Vm<X86, P>> {
    fn spawn(self: Arc<Self>) -> Result<Box<dyn Thread>> {
        let keep = self.write().unwrap();
        let id = 0;

        let vcpu = keep.fd.create_vcpu(id as _)?;

        vcpu.set_cpuid2(&keep.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?)?;

        let thread = Cpu::new(vcpu, self.clone(), keep.arch.rip, keep.arch.cr3)?;
        Ok(Box::new(thread))
    }
}
