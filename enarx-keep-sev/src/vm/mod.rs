// SPDX-License-Identifier: Apache-2.0

pub mod builder;
mod cpu;
mod mem;

pub use builder::Builder;
use mem::Region;

use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use x86_64::PhysAddr;

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

        loop {
            match cpu0.run()? {
                VcpuExit::IoOut(port, data) => {
                    println!("IoOut: received {} bytes from port {}", data.len(), port);
                }
                exit_reason => {
                    println!("{:?}", exit_reason);
                    println!("{:?}", cpu0.get_regs());
                    println!("{:?}", cpu0.get_sregs());
                    break;
                }
            }
        }

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
