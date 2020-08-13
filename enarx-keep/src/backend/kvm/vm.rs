// SPDX-License-Identifier: Apache-2.0

pub mod builder;
mod cpu;
mod mem;
mod x86_64;

pub use builder::Builder;
use cpu::{Allocator, Cpu};
use mem::Region;

use crate::backend::{Keep, Thread};

use ::x86_64::PhysAddr;
use anyhow::Result;
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VmFd};

use std::sync::{Arc, RwLock};

pub struct VirtualMachine {
    kvm: Kvm,
    fd: VmFd,
    id_alloc: Allocator,
    address_space: Region,
    shim_entry: PhysAddr,
    shim_start: PhysAddr,
}

impl Keep for RwLock<VirtualMachine> {
    fn add_thread(self: Arc<Self>) -> Result<Box<dyn Thread>> {
        let mut keep = self.write().unwrap();
        let id = keep.id_alloc.next();
        let address_space = keep.address_space.as_virt();
        let prefix = keep.address_space.prefix_mut();

        let vcpu = keep.fd.create_vcpu(id as _)?;

        let mut regs = vcpu.get_regs()?;
        if id == 0 {
            regs.rsi = keep.shim_start.as_u64();
            regs.rdi = &prefix.shared_pages[0] as *const _ as u64 - address_space.start.as_u64();
        } else {
            unimplemented!()
        }

        vcpu.set_regs(&regs)?;
        vcpu.set_cpuid2(&keep.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?)?;

        let cr3 = &*prefix.pml4t as *const _ as u64 - address_space.start.as_u64();

        let thread = Cpu::new(vcpu, id, self.clone(), keep.shim_entry, cr3)?;
        Ok(Box::new(thread))
    }
}
