// SPDX-License-Identifier: Apache-2.0

use crate::backend::kvm;

use sev::certs::Chain;
use sev::firmware::Firmware;
use sev::launch::{Launcher, Policy};
use sev::session::Session;

use kvm_ioctls::VmFd;
use x86_64::{PhysAddr, VirtAddr};

use anyhow::Result;
use std::convert::TryFrom;
use std::env;
use std::fs::File;
use std::io::{Error, ErrorKind};

pub struct Sev;

impl kvm::Hook for Sev {
    fn code_loaded(&mut self, vm: &mut VmFd, addr_space: &[u8]) -> Result<()> {
        use codicon::Decoder;

        let mut sev = Firmware::open()?;
        let build = sev.platform_status().unwrap().build;

        let chain = env::var_os("SEV_CHAIN").ok_or_else(|| Error::from(ErrorKind::NotFound))?;

        let mut chain = File::open(chain)?;
        let chain = Chain::decode(&mut chain, ())?;

        let policy = Policy::default();
        let session = Session::try_from(policy)?;
        let start = session.start(chain)?;
        let mut session = session.measure()?;
        session.update_data(addr_space)?;

        let (launcher, measurement) = {
            let launcher = Launcher::new(vm, &mut sev)?;
            let mut launcher = launcher.start(start)?;
            launcher.update_data(addr_space)?;
            let launcher = launcher.measure()?;
            let measurement = launcher.measurement();
            (launcher, measurement)
        };

        let _ = session.verify(build, measurement)?;
        let _handle = launcher.finish()?;

        Ok(())
    }

    fn to_guest_phys(&self, addr: VirtAddr, start: VirtAddr) -> PhysAddr {
        use core::arch::x86_64::__cpuid_count;
        let c_bit_loc = unsafe { __cpuid_count(0x8000_001f, 0x0000_0000) }.ebx;
        let c_bit_loc = c_bit_loc & 0x3f;

        PhysAddr::new((addr.as_u64() - start.as_u64()) | 1 << c_bit_loc)
    }
}
