// SPDX-License-Identifier: Apache-2.0

use super::mem::Region;
use anyhow::{Error, Result};
use kvm_bindings::bindings::kvm_userspace_memory_region;
use kvm_bindings::fam_wrappers::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VmFd};
use mmarinus::{perms, Map};
use sallyport::Block;
use std::convert::TryFrom;
use std::mem::size_of;
use std::sync::{Arc, RwLock};
use x86_64::VirtAddr;

pub struct Builder {
    kvm_fd: Kvm,
    vm_fd: VmFd,
    regions: Vec<Region>,
    sallyports: Vec<Option<VirtAddr>>,
}

impl TryFrom<super::config::Config> for Builder {
    type Error = Error;

    fn try_from(_config: super::config::Config) -> Result<Self> {
        let kvm_fd = Kvm::new()?;
        let vm_fd = kvm_fd.create_vm()?;

        Ok(Builder {
            kvm_fd,
            vm_fd,
            regions: Vec::new(),
            sallyports: Vec::new(),
        })
    }
}

impl super::super::Mapper for Builder {
    type Config = super::config::Config;
    type Output = Arc<dyn super::super::Keep>;

    fn map(
        &mut self,
        pages: Map<perms::ReadWrite>,
        to: usize,
        sallyport: bool,
    ) -> anyhow::Result<()> {
        // Ignore regions with no pages.
        if pages.is_empty() {
            return Ok(());
        }

        if sallyport {
            for start in (0..pages.size()).step_by(size_of::<Block>()) {
                if start + size_of::<Block>() <= pages.size() {
                    let virt = VirtAddr::from_ptr(pages.as_ptr()) + start;
                    self.sallyports.push(Some(virt));
                }
            }
        }

        let mem_region = kvm_userspace_memory_region {
            slot: self.regions.len() as _,
            flags: 0,
            guest_phys_addr: to as _,
            memory_size: pages.size() as _,
            userspace_addr: pages.addr() as _,
        };

        unsafe { self.vm_fd.set_user_memory_region(mem_region)? };

        self.regions.push(Region::new(mem_region, pages));

        Ok(())
    }
}

impl TryFrom<Builder> for Arc<dyn super::super::Keep> {
    type Error = Error;

    fn try_from(builder: Builder) -> Result<Self> {
        // If no LOAD segment were defined as sallyport blocks
        if builder.sallyports.is_empty() {
            anyhow::bail!("No sallyport blocks defined!");
        }

        let cpuids = builder.kvm_fd.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;

        let vcpu_fd = builder.vm_fd.create_vcpu(0)?;
        vcpu_fd.set_cpuid2(&cpuids)?;

        // FIXME: this will be removed with relative addresses in sallyport
        // unwrap, because we have at least one block
        let sallyport_block_start = builder.sallyports.first().unwrap().unwrap();

        Ok(Arc::new(RwLock::new(super::Keep {
            kvm_fd: builder.kvm_fd,
            vm_fd: builder.vm_fd,
            cpu_fds: vec![vcpu_fd],
            regions: builder.regions,
            sallyports: builder.sallyports,
            sallyport_start: sallyport_block_start,
        })))
    }
}
