// SPDX-License-Identifier: Apache-2.0

use super::mem::Region;
use super::KvmKeepPersonality;

use std::convert::TryFrom;
use std::mem::size_of;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Error, Result};
use kvm_bindings::bindings::kvm_userspace_memory_region;
use kvm_bindings::fam_wrappers::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use mmarinus::{perms, Map};
use sallyport::elf::pf::kvm::SALLYPORT;
use sallyport::Block;
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
        let kvm_fd = Kvm::new().context("Failed to open '/dev/kvm'")?;
        let vm_fd = kvm_fd
            .create_vm()
            .context("Failed to create a virtual machine")?;

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
        mut pages: Map<perms::ReadWrite>,
        to: usize,
        with: u32,
    ) -> anyhow::Result<()> {
        // Ignore regions with no pages.
        if pages.is_empty() {
            return Ok(());
        }

        let mem_region = kvm_builder_map(
            &mut self.sallyports,
            &mut self.vm_fd,
            &mut pages,
            to,
            with,
            self.regions.len() as _,
        )?;

        self.regions.push(Region::new(mem_region, pages));

        Ok(())
    }
}

pub fn kvm_builder_map(
    sallyports: &mut Vec<Option<VirtAddr>>,
    vm_fd: &mut VmFd,
    pages: &mut Map<perms::ReadWrite>,
    to: usize,
    with: u32,
    slot: u32,
) -> anyhow::Result<kvm_userspace_memory_region> {
    if with & SALLYPORT != 0 {
        for start in (0..pages.size()).step_by(size_of::<Block>()) {
            if start + size_of::<Block>() <= pages.size() {
                let virt = VirtAddr::from_ptr(pages.as_ptr()) + start;
                sallyports.push(Some(virt));
            }
        }
    }

    let mem_region = kvm_userspace_memory_region {
        slot,
        flags: 0,
        guest_phys_addr: to as _,
        memory_size: pages.size() as _,
        userspace_addr: pages.addr() as _,
    };

    unsafe {
        vm_fd
            .set_user_memory_region(mem_region)
            .context("Failed to set user memory region")?
    };
    Ok(mem_region)
}

impl TryFrom<Builder> for Arc<dyn super::super::Keep> {
    type Error = Error;

    fn try_from(mut builder: Builder) -> Result<Self> {
        let (vcpu_fd, sallyport_block_start) =
            kvm_try_from_builder(&builder.sallyports, &mut builder.kvm_fd, &mut builder.vm_fd)?;

        Ok(Arc::new(RwLock::new(super::Keep::<KvmKeepPersonality> {
            kvm_fd: builder.kvm_fd,
            vm_fd: builder.vm_fd,
            cpu_fds: vec![vcpu_fd],
            regions: builder.regions,
            sallyports: builder.sallyports,
            sallyport_start: sallyport_block_start,
            personality: KvmKeepPersonality(()),
        })))
    }
}

pub fn kvm_try_from_builder(
    sallyports: &[Option<VirtAddr>],
    kvm_fd: &mut Kvm,
    vm_fd: &mut VmFd,
) -> Result<(VcpuFd, VirtAddr)> {
    // If no LOAD segment were defined as sallyport blocks
    if sallyports.is_empty() {
        anyhow::bail!("No sallyport blocks defined!");
    }

    let cpuids = kvm_fd
        .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
        .context("Failed to get supported CPUID entries from kvm")?;

    let vcpu_fd = vm_fd
        .create_vcpu(0)
        .context("Failed to create a virtual CPU")?;
    vcpu_fd
        .set_cpuid2(&cpuids)
        .context("Failed to set the supported CPUID entries")?;

    // FIXME: this will be removed with relative addresses in sallyport
    // unwrap, because we have at least one block
    let sallyport_block_start = sallyports.first().unwrap().unwrap();
    Ok((vcpu_fd, sallyport_block_start))
}
