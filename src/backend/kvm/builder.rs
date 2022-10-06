// SPDX-License-Identifier: Apache-2.0

use super::config::Config;
use super::mem::{Region, Slot};
use super::KvmKeepPersonality;

use std::convert::TryFrom;
use std::mem::align_of;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Error, Result};
use kvm_bindings::fam_wrappers::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use mmarinus::{perms, Map};
use sallyport::elf::pf::kvm::SALLYPORT;
use x86_64::{align_up, VirtAddr};

pub struct Builder {
    config: Config,
    kvm_fd: Kvm,
    vm_fd: VmFd,
    regions: Vec<Region>,
    sallyports: Vec<Option<VirtAddr>>,
}

impl TryFrom<super::config::Config> for Builder {
    type Error = Error;

    fn try_from(config: Config) -> Result<Self> {
        let kvm_fd = Kvm::new().context("Failed to open '/dev/kvm'")?;
        let vm_fd = kvm_fd
            .create_vm()
            .context("Failed to create a virtual machine")?;

        Ok(Builder {
            config,
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

    fn map(&mut self, pages: Map<perms::ReadWrite>, to: usize, with: u32) -> anyhow::Result<()> {
        // Ignore regions with no pages.
        if pages.is_empty() {
            return Ok(());
        }

        if with & SALLYPORT != 0 {
            map_sallyports(
                &pages,
                self.config.sallyport_block_size,
                &mut self.sallyports,
            );
        }

        let slot = Slot::new(
            &mut self.vm_fd,
            self.regions.len() as u32,
            &pages,
            to as u64,
            false,
        )?;

        self.regions.push(Region::new(slot, pages));

        Ok(())
    }
}

pub fn map_sallyports(
    pages: &Map<perms::ReadWrite>,
    block_size: usize,
    sallyports: &mut Vec<Option<VirtAddr>>,
) {
    for start in (0..pages.size()).step_by(block_size) {
        let start = align_up(start as u64, align_of::<usize>() as u64) as usize;
        if start + block_size <= pages.size() {
            let virt = VirtAddr::from_ptr(pages.as_ptr()) + start;
            sallyports.push(Some(virt));
        }
    }
}

impl TryFrom<Builder> for Arc<dyn super::super::Keep> {
    type Error = Error;

    fn try_from(mut builder: Builder) -> Result<Self> {
        let vcpu_fd =
            kvm_try_from_builder(&builder.sallyports, &mut builder.kvm_fd, &mut builder.vm_fd)?;

        Ok(Arc::new(RwLock::new(super::Keep::<KvmKeepPersonality> {
            kvm_fd: builder.kvm_fd,
            vm_fd: builder.vm_fd,
            cpu_fds: vec![vcpu_fd],
            regions: builder.regions,
            sallyport_block_size: builder.config.sallyport_block_size,
            sallyports: builder.sallyports,
            personality: KvmKeepPersonality(()),
        })))
    }
}

pub fn kvm_try_from_builder(
    sallyports: &[Option<VirtAddr>],
    kvm_fd: &mut Kvm,
    vm_fd: &mut VmFd,
) -> Result<VcpuFd> {
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

    Ok(vcpu_fd)
}
