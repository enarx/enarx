// SPDX-License-Identifier: Apache-2.0

use super::cpuid_page::CpuidPage;
use super::snp::firmware::Firmware;
use super::snp::launch::*;

use super::SnpKeepPersonality;
use crate::backend::kvm::builder::kvm_try_from_builder;
use crate::backend::kvm::mem::Region;

use std::convert::TryFrom;
use std::sync::{Arc, RwLock};
use std::{thread, time};

use anyhow::{Context, Error};
use kvm_ioctls::Kvm;
use mmarinus::{perms, Map};
use primordial::Page;
use rand::{thread_rng, Rng};
use sallyport::elf::pf::snp::{CPUID, SECRETS};
use x86_64::VirtAddr;

const SEV_RETRIES: usize = 3;
const SEV_RETRY_SLEEP_MS: u64 = 500;

pub struct Builder {
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

impl TryFrom<super::super::kvm::config::Config> for Builder {
    type Error = Error;

    fn try_from(_config: super::super::kvm::config::Config) -> anyhow::Result<Self> {
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
            policy: Policy {
                flags: PolicyFlags::SMT,
                ..Default::default()
            },
            gosvw: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            ..Default::default()
        };

        let launcher = launcher.start(start).context("SNP Launcher start failed")?;

        Ok(Builder {
            kvm_fd,
            launcher,
            regions: Vec::new(),
            sallyports: Vec::new(),
        })
    }
}

impl super::super::Mapper for Builder {
    type Config = super::super::kvm::config::Config;
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

        let mem_region = super::super::kvm::builder::kvm_builder_map(
            &mut self.sallyports,
            self.launcher.as_mut(),
            &mut pages,
            to,
            with,
            self.regions.len() as _,
        )?;

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
                &pages,
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

    fn try_from(mut builder: Builder) -> anyhow::Result<Self> {
        let (vcpu_fd, sallyport_block_start) = kvm_try_from_builder(
            &builder.sallyports,
            &mut builder.kvm_fd,
            builder.launcher.as_mut(),
        )?;

        let finish = Finish::new(None, None, [0u8; 32]);

        let (vm_fd, sev_fd) = builder
            .launcher
            .finish(finish)
            .context("SNP Launcher finish failed")?;

        Ok(Arc::new(RwLock::new(super::Keep::<SnpKeepPersonality> {
            kvm_fd: builder.kvm_fd,
            vm_fd,
            cpu_fds: vec![vcpu_fd],
            regions: builder.regions,
            sallyports: builder.sallyports,
            sallyport_start: sallyport_block_start,
            personality: SnpKeepPersonality { _sev_fd: sev_fd },
        })))
    }
}
