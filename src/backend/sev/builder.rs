// SPDX-License-Identifier: Apache-2.0

use crate::backend::kvm;
use crate::backend::kvm::shim::{BootInfo, SevSecret};
use crate::backend::kvm::Hv2GpFn;

use sev::firmware::Firmware;
use sev::launch::{Launcher, Secret};

use ciborium::{de::from_reader, ser::into_writer};
use codicon::{Decoder, Encoder};
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
    fn code_loaded(
        &mut self,
        vm: &mut VmFd,
        addr_space: &[u8],
        syscall_blocks: VirtAddr,
    ) -> Result<()> {
        let mut sev = Firmware::open()?;
        let build = sev.platform_status().unwrap().build;

        let chain = sev::cached_chain::get()?;
        let mut chain_container = Chain {
            ark: vec![],
            ask: vec![],
            oca: vec![],
            cek: vec![],
            pek: vec![],
            pdh: vec![],
        };
        chain.ca.ark.encode(&mut chain_container.ark, ())?;
        chain.ca.ask.encode(&mut chain_container.ask, ())?;
        chain.sev.oca.encode(&mut chain_container.oca, ())?;
        chain.sev.cek.encode(&mut chain_container.cek, ())?;
        chain.sev.pek.encode(&mut chain_container.pek, ())?;
        chain.sev.pdh.encode(&mut chain_container.pdh, ())?;

        let generation = sev::Generation::try_from(&chain.sev)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))?;
        let chain_packet = match generation {
            sev::Generation::Naples => Message::CertificateChainNaples(chain_container),
            sev::Generation::Rome => Message::CertificateChainRome(chain_container),
        };
        into_writer(&chain_packet, &self.0)?;

        let start_packet = from_reader(&self.0)?;
        let start_packet = match start_packet {
            Message::LaunchStart(ls) => LaunchStart {
                policy: ls.policy,
                cert: ls.cert,
                session: ls.session,
            },
            _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into()),
        };

        let start = sev::launch::Start {
            policy: from_reader(start_packet.policy.as_slice())?,
            cert: sev::certs::sev::Certificate::decode(start_packet.cert.as_slice(), ())?,
            session: from_reader(start_packet.session.as_slice())?,
        };

        let (mut launcher, measurement) = {
            let launcher = Launcher::new(vm, &mut sev)?;
            let mut launcher = launcher.start(start)?;
            launcher.update_data(addr_space)?;
            let launcher = launcher.measure()?;
            let measurement = launcher.measurement();
            (launcher, measurement)
        };

        let mut msr_container = Measurement {
            build: vec![],
            measurement: vec![],
        };
        into_writer(&build, &mut msr_container.build)?;
        into_writer(&measurement, &mut msr_container.measurement)?;
        let msr_packet = Message::Measurement(msr_container);
        into_writer(&msr_packet, &self.0)?;

        let secret = match from_reader(&self.0)? {
            Message::Secret(bytes) => bytes,
            _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into()),
        };

        if !secret.is_empty() {
            let secret: Secret = from_reader(secret.as_slice())?;

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
