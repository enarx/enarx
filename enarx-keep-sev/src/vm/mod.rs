// SPDX-License-Identifier: Apache-2.0

pub mod builder;
mod cpu;
mod mem;
mod syscall;

pub use builder::Builder;
use mem::Region;

use enarx_keep_sev_shim::SYSCALL_TRIGGER_PORT;
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use x86_64::{PhysAddr, VirtAddr};

use std::io;

pub struct VirtualMachine {
    kvm: Kvm,
    fd: VmFd,
    address_space: Region,
    cpus: Vec<VcpuFd>,
    sallyport: VirtAddr,
}

impl VirtualMachine {
    pub fn start(&self) -> Result<(), io::Error> {
        let cpu0 = self.cpus.first().unwrap();

        loop {
            match cpu0.run()? {
                VcpuExit::IoOut(port, _) => match port {
                    SYSCALL_TRIGGER_PORT => {
                        let req = self.sallyport.as_mut_ptr::<sallyport::Request>();
                        let fixup_offset = self.address_space.as_virt().start.as_u64();
                        unsafe {
                            let reply = syscall::syscall(*req, fixup_offset);
                            self.sallyport
                                .as_mut_ptr::<sallyport::Reply>()
                                .write_volatile(reply);
                        };
                    }
                    _ => return Err(io::ErrorKind::InvalidInput.into()),
                },
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

    fn add_vcpu(&mut self, vcpu: VcpuFd, entry: PhysAddr, cr3: u64) -> Result<(), io::Error> {
        cpu::set_gen_regs(&vcpu, entry)?;
        cpu::set_special_regs(&vcpu, cr3)?;
        vcpu.set_cpuid2(&self.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?)?;

        self.cpus.push(vcpu);
        Ok(())
    }
}
