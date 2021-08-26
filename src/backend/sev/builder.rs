// SPDX-License-Identifier: Apache-2.0

use crate::backend::kvm::{self, measure};

use sev::firmware::Firmware;
use sev::launch::Launcher;

use ciborium::{de::from_reader, ser::into_writer};
use koine::attestation::sev::*;
use kvm_ioctls::VmFd;
use x86_64::VirtAddr;

use anyhow::{Context, Result};
use std::convert::TryFrom;
use std::os::unix::net::UnixStream;

pub struct Sev(UnixStream);

impl Sev {
    pub fn new(sock: UnixStream) -> Self {
        Self(sock)
    }
}

impl kvm::Hook for Sev {
    fn preferred_digest() -> measure::Kind {
        measure::Kind::Sha256
    }

    fn code_loaded(
        &mut self,
        vm: &mut VmFd,
        addr_space: &[u8],
        syscall_blocks: VirtAddr,
    ) -> Result<()> {
        let mut sev = Firmware::open()?;
        let build = sev.platform_status().unwrap().build;

        let chain = sev::cached_chain::get().with_context(|| {
            "Failed to read cached certification chain from `/var/cache/amd-sev/chain`"
        })?;

        let generation = sev::Generation::try_from(&chain.sev)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))?;
        let chain_packet = match generation {
            sev::Generation::Naples => Message::CertificateChainNaples(chain),
            sev::Generation::Rome => Message::CertificateChainRome(chain),
            sev::Generation::Milan => Message::CertificateChainMilan(chain),
        };
        into_writer(&chain_packet, &self.0)?;

        let start_packet = from_reader(&self.0)?;
        let start = match start_packet {
            Message::LaunchStart(ls) => ls,
            _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into()),
        };

        let (mut launcher, measurement) = {
            let launcher = Launcher::new(vm, &mut sev)?;
            let mut launcher = launcher.start(start)?;
            launcher.update_data(addr_space)?;
            let launcher = launcher.measure()?;
            let measurement = launcher.measurement();
            (launcher, measurement)
        };

        let measurement = Measurement { build, measurement };
        let msr_packet = Message::Measurement(measurement);
        into_writer(&msr_packet, &self.0)?;

        let secret = match from_reader(&self.0)? {
            Message::Secret(secret) => secret,
            _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into()),
        };

        if let Some(secret) = secret {
            let secret_ptr = syscall_blocks.as_ptr::<u8>() as usize;
            if secret_ptr & (16 - 1) != 0 {
                return Err(anyhow::anyhow!(
                    "sallyport blocks not aligned for sev secret"
                ));
            }
            launcher.inject(&secret, secret_ptr)?;
        }

        let finish_packet = Message::Finish(Finish);
        into_writer(&finish_packet, &self.0)?;

        let _handle = launcher.finish()?;

        Ok(())
    }
}
