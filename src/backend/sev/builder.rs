// SPDX-License-Identifier: Apache-2.0

use super::cpuid_page::CpuidPage;
use super::snp::firmware::Firmware;
use super::snp::launch::*;

use super::SnpKeepPersonality;
use crate::backend::kvm::builder::{kvm_try_from_builder, map_sallyports};
use crate::backend::kvm::mem::Region;
use crate::backend::sev::config::Config;
use crate::backend::ByteSized;

use std::convert::TryFrom;
use std::sync::{Arc, RwLock};
use std::{thread, time};

use anyhow::{anyhow, Context, Error};
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::Kvm;
use mmarinus::{perms, Map};
use primordial::Page;
use rand::{thread_rng, Rng};
use sallyport::elf::pf::kvm::SALLYPORT;
use sallyport::elf::pf::snp::{CPUID, SECRETS};
use x86_64::VirtAddr;

const SEV_RETRIES: usize = 3;
const SEV_RETRY_SLEEP_MS: u64 = 500;

pub struct Builder {
    config: Config,
    kvm_fd: Kvm,
    launcher: Launcher<Started, Firmware>,
    regions: Vec<Region>,
    sallyports: Vec<Option<VirtAddr>>,
}

fn retry<O>(func: impl Fn() -> anyhow::Result<O>) -> anyhow::Result<O> {
    let mut retries = SEV_RETRIES;
    let mut rng = thread_rng();
    loop {
        match func() {
            Err(e) if retries > 0 => {
                retries -= 1;
                eprintln!(
                    "Error {:#?}.\nRetry {} of {}.",
                    e,
                    SEV_RETRIES - retries,
                    SEV_RETRIES
                );
                let millis =
                    time::Duration::from_millis(SEV_RETRY_SLEEP_MS + rng.gen::<u8>() as u64);
                thread::sleep(millis);
                continue;
            }
            Err(e) => {
                return Err(e);
            }
            Ok(o) => {
                return Ok(o);
            }
        }
    }
}

impl TryFrom<super::config::Config> for Builder {
    type Error = Error;

    fn try_from(config: super::config::Config) -> anyhow::Result<Self> {
        let (kvm_fd, launcher) = retry(|| {
            // try to open /dev/sev and start the Launcher several times

            let kvm_fd = Kvm::new().context("Failed to open '/dev/kvm'")?;
            let vm_fd = kvm_fd
                .create_vm()
                .context("Failed to create a virtual machine")?;

            let sev = retry(|| Firmware::open().context("Failed to open '/dev/sev'"))?;
            let launcher = Launcher::new(vm_fd, sev).context("SNP Launcher init failed")?;

            Ok((kvm_fd, launcher))
        })?;

        let start = Start {
            policy: config.parameters.policy,
            ..Default::default()
        };

        let launcher = launcher.start(start).context("SNP Launcher start failed")?;

        Ok(Builder {
            config,
            kvm_fd,
            launcher,
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
        let slot = self.regions.len() as _;

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

        let mem_region = kvm_userspace_memory_region {
            slot,
            flags: 0,
            guest_phys_addr: to as _,
            memory_size: pages.size() as _,
            userspace_addr: pages.addr() as _,
        };

        unsafe {
            self.launcher
                .as_mut()
                .set_user_memory_region(mem_region)
                .context("Failed to set user memory region")?
        };

        let dp = VmplPerms::empty();

        if with & CPUID != 0 {
            assert_eq!(pages.len(), Page::SIZE);
            let mut cpuid_page = CpuidPage::default();
            cpuid_page
                .import_from_kvm(&mut self.kvm_fd)
                .context("Failed to create CPUID page")?;

            let guest_cpuid_page = pages.as_mut_ptr() as *mut CpuidPage;
            unsafe {
                guest_cpuid_page.write(cpuid_page);
            }

            let update = Update::new(
                to as u64 >> 12,
                &pages,
                false,
                PageType::Cpuid,
                (dp, dp, dp),
            );

            if self.launcher.update_data(update).is_err() {
                // Just try again with the firmware corrected values
                self.launcher
                    .update_data(update)
                    .context("launcher.update_data for CPUID failed")?;
            }
        } else if with & SECRETS != 0 {
            assert_eq!(pages.len(), Page::SIZE);

            let update = Update::new(
                to as u64 >> 12,
                &pages,
                false,
                PageType::Secrets,
                (dp, dp, dp),
            );

            self.launcher
                .update_data(update)
                .context("SNP Launcher update_data failed")?;
        } else {
            let update = Update::new(
                to as u64 >> 12,
                pages.as_ref(),
                false,
                PageType::Normal,
                (dp, dp, dp),
            );

            self.launcher
                .update_data(update)
                .context("SNP Launcher update_data failed")?;
        };

        self.regions.push(Region::new(mem_region, pages));

        Ok(())
    }
}

impl TryFrom<Builder> for Arc<dyn super::super::Keep> {
    type Error = Error;

    fn try_from(builder: Builder) -> anyhow::Result<Self> {
        let Builder {
            mut config,
            mut kvm_fd,
            mut launcher,
            regions,
            sallyports,
        } = builder;

        let sallyport_block_size = config.sallyport_block_size;
        let signatures = config.signatures.take();

        let id_block;
        let id_auth;

        let vcpu_fd = kvm_try_from_builder(&sallyports, &mut kvm_fd, launcher.as_mut())?;

        let finish = if let Some(signatures) = signatures {
            let sig_blob = signatures.sev;

            id_auth = IdAuth::from_bytes(&sig_blob.id_auth)
                .ok_or_else(|| anyhow!("Invalid SEV signature IdAuth blob size."))?;
            id_block = IdBlock::from_bytes(&sig_blob.id_block)
                .ok_or_else(|| anyhow!("Invalid SEV signature IdBlock blob size."))?;

            Finish::new(Some((&id_block, &id_auth)), true, [0u8; 32])
        } else {
            Finish::new(None, false, [0u8; 32])
        };

        let (vm_fd, sev_fd) = launcher
            .finish(finish)
            .context("SNP Launcher finish failed")?;

        Ok(Arc::new(RwLock::new(super::Keep::<SnpKeepPersonality> {
            kvm_fd,
            vm_fd,
            cpu_fds: vec![vcpu_fd],
            regions,
            sallyport_block_size,
            sallyports,
            personality: SnpKeepPersonality { _sev_fd: sev_fd },
        })))
    }
}
