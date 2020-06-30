// SPDX-License-Identifier: Apache-2.0

pub mod builder;
mod cpu;
mod mem;

pub use builder::Builder;
use mem::Region;

use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use x86_64::PhysAddr;

use kvm_bindings::KVM_MAX_CPUID_ENTRIES;

use std::io;

pub struct VirtualMachine {
    kvm: Kvm,
    fd: VmFd,
    address_space: Region,
    cpus: Vec<VcpuFd>,
}

impl VirtualMachine {
    pub fn start(&self) -> Result<(), io::Error> {
        let cpu0 = self.cpus.first().unwrap();

        Ok(())
    }

    fn add_vcpu(&mut self, vcpu: VcpuFd, entry: PhysAddr) -> Result<(), io::Error> {
        cpu::set_gen_regs(&vcpu, entry)?;
        cpu::set_special_regs(&vcpu)?;
        vcpu.set_cpuid2(&self.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?)?;

        self.cpus.push(vcpu);
        Ok(())
    }
}
