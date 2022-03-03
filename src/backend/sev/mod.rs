// SPDX-License-Identifier: Apache-2.0

pub use snp::certs;
pub use snp::firmware::Firmware;

use super::kvm::mem::Region;
use super::kvm::{Keep, KeepPersonality};
use super::probe::common::system_info;
use super::Loader;

use std::sync::Arc;

use anyhow::Result;
use data::{
    dev_kvm, dev_sev, dev_sev_readable, dev_sev_writable, has_reasonable_memlock_rlimit,
    kvm_version, sev_enabled_in_kernel, CPUIDS,
};

use kvm_bindings::bindings::kvm_enc_region;
use kvm_ioctls::VmFd;

mod builder;
mod cpuid_page;
mod data;
mod snp;

struct SnpKeepPersonality {
    // Must be kept open for the VM to talk to the SEV Firmware
    _sev_fd: Firmware,
}

impl KeepPersonality for SnpKeepPersonality {
    fn map(vm_fd: &mut VmFd, region: &Region) -> std::io::Result<()> {
        let memory_region = kvm_enc_region {
            addr: region.backing().as_ptr() as _,
            size: region.backing().len() as _,
        };
        vm_fd.register_enc_memory_region(&memory_region).unwrap();
        Ok(())
    }
}

pub struct Backend;

impl super::Backend for Backend {
    #[inline]
    fn name(&self) -> &'static str {
        "sev"
    }

    #[inline]
    fn shim(&self) -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-sev"))
    }

    #[inline]
    fn have(&self) -> bool {
        self.data().iter().all(|x| x.pass)
    }

    fn data(&self) -> Vec<super::Datum> {
        let mut data = vec![
            system_info(),
            dev_sev(),
            sev_enabled_in_kernel(),
            dev_sev_readable(),
            dev_sev_writable(),
            dev_kvm(),
            kvm_version(),
            has_reasonable_memlock_rlimit(),
        ];
        data.extend(CPUIDS.iter().map(|c| c.into()));
        data
    }

    #[inline]
    fn keep(&self, shim: &[u8], exec: &[u8]) -> Result<Arc<dyn super::Keep>> {
        builder::Builder::load(shim, exec)
    }

    #[inline]
    fn hash(&self, _shim: &[u8], _exec: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
