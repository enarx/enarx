// SPDX-License-Identifier: Apache-2.0

use crate::backend::kvm::shim::{BootInfo, SevSecret};
use crate::backend::kvm::Hv2GpFn;
use crate::backend::kvm::{self, measure};

use sev::firmware::Firmware;
use sev::launch::Launcher;

use ciborium::{de::from_reader, ser::into_writer};
use koine::attestation::sev::*;
use kvm_ioctls::VmFd;
use x86_64::{PhysAddr, VirtAddr};

use anyhow::Result;
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

        let chain = sev::cached_chain::get()?;

        let generation = sev::Generation::try_from(&chain.sev)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))?;
        let chain_packet = match generation {
            sev::Generation::Naples => Message::CertificateChainNaples(chain),
            sev::Generation::Rome => Message::CertificateChainRome(chain),
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
            let secret_ptr = SevSecret::get_secret_ptr(syscall_blocks.as_ptr::<BootInfo>());
            launcher.inject(secret, secret_ptr as _)?;
        }

        let finish_packet = Message::Finish(Finish);
        into_writer(&finish_packet, &self.0)?;

        let _handle = launcher.finish()?;

        Ok(())
    }

    fn hv2gp(&self) -> Box<Hv2GpFn> {
        use core::arch::x86_64::__cpuid_count;
        let c_bit_loc = unsafe { __cpuid_count(0x8000_001f, 0x0000_0000) }.ebx;
        let c_bit_loc = c_bit_loc & 0x3f;

        Box::new(move |target, start| {
            PhysAddr::new((target.as_u64() - start.as_u64()) | 1 << c_bit_loc)
        })
    }
}
