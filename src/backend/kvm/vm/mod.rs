// SPDX-License-Identifier: Apache-2.0

pub mod builder;
mod cpu;
pub mod image;
mod mem;
pub mod personality;

use crate::backend::kvm::shim::MAX_SETUP_SIZE;
use crate::backend::{Keep, Thread};

use cpu::Cpu;
use mem::Region;
use personality::Personality;

pub use builder::{Builder, Hook, Hv2GpFn};
pub use image::{x86::X86, Arch};
pub use kvm_bindings::kvm_segment as KvmSegment;
pub use kvm_bindings::kvm_userspace_memory_region as KvmUserspaceMemoryRegion;

use anyhow::Result;
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VmFd};
use lset::Span;
use mmarinus::{perms, Kind, Map};
use primordial::Page;
use x86_64::{PhysAddr, VirtAddr};

use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

pub struct Vm<A: Arch, P: Personality> {
    kvm: Kvm,
    fd: VmFd,
    regions: Vec<Region>,
    syscall_blocks: Span<VirtAddr, NonZeroUsize>,
    shim_entry: PhysAddr,
    shim_start: PhysAddr,
    hv2gp: Box<Hv2GpFn>,
    arch: VirtAddr,
    _phantom: PhantomData<A>,
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
    fn add_thread(self: Arc<Self>) -> Result<Box<dyn Thread>> {
        let keep = self.write().unwrap();
        let id = 0;
        let region_zero = &keep.regions[0];
        let address_space = region_zero.as_virt();

        let vcpu = keep.fd.create_vcpu(id as _)?;

        let mut regs = vcpu.get_regs()?;
        if id == 0 {
            regs.rsi = keep.shim_start.as_u64();
            regs.rdi = keep.syscall_blocks.start.as_u64() - address_space.start.as_u64();
        } else {
            unimplemented!()
        }

        vcpu.set_regs(&regs)?;
        vcpu.set_cpuid2(&keep.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?)?;

        let arch = unsafe { &*(keep.arch.as_ptr() as *const X86) };
        let cr3 = (keep.hv2gp)(VirtAddr::from_ptr(&arch.pml4t), address_space.start);

        let thread = Cpu::new(vcpu, self.clone(), keep.shim_entry, cr3)?;
        Ok(Box::new(thread))
    }
}
