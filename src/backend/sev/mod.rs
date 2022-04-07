// SPDX-License-Identifier: Apache-2.0

pub use snp::firmware::Firmware;

use super::kvm::mem::Region;
use super::kvm::{Keep, KeepPersonality};
use super::probe::common::system_info;
use super::Loader;
use crate::cli::snp::get_vcek_reader;
use data::{
    dev_kvm, dev_sev, dev_sev_readable, dev_sev_writable, has_reasonable_memlock_rlimit,
    kvm_version, sev_enabled_in_kernel, CPUIDS,
};

use std::io;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use kvm_bindings::bindings::kvm_enc_region;
use kvm_ioctls::VmFd;
use sallyport::host::deref_slice;
use sallyport::item::enarxcall::Payload;
use sallyport::item::{self, Item};

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
    fn enarxcall<'a>(
        &mut self,
        enarxcall: &'a mut Payload,
        data: &'a mut [u8],
    ) -> Result<Option<Item<'a>>> {
        match enarxcall {
            item::Enarxcall {
                num: item::enarxcall::Number::GetSnpVcek,
                argv: [vcek_offset, vcek_len, ..],
                ret,
            } => {
                let mut vcek_buf: &mut [u8] = unsafe {
                    // Safety: `deref_slice` gives us a pointer to a byte slice, which does not have to be aligned.
                    // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                    // is a subslice of.
                    &mut *deref_slice::<u8>(data, *vcek_offset, *vcek_len)
                        .map_err(io::Error::from_raw_os_error)
                        .context("snp::enarxcall deref")?
                };
                let mut vcek_reader = get_vcek_reader()?;
                *ret = std::io::copy(&mut vcek_reader, &mut vcek_buf)? as _;
                if *ret == 0 {
                    bail!("Could not get SEV-SNP vcek! Run `enarx snp vcek update`")
                }
                Ok(None)
            }
            _ => return Ok(Some(Item::Enarxcall(enarxcall, data))),
        }
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
        include_bytes!(env!("CARGO_BIN_FILE_ENARX_SHIM_KVM"))
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
