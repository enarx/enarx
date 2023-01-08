// SPDX-License-Identifier: Apache-2.0

pub mod snp;

use iocuddle::{Group, Ioctl, WriteRead};
pub use snp::firmware::Firmware;

mod builder;
mod config;
mod cpuid_page;
mod data;
mod hasher;

use snp::vcek::SnpEvidence;

use super::kvm::mem::Region;
use super::kvm::{Keep, KeepPersonality};
use super::Loader;
use data::{
    dev_kvm, dev_sev, dev_sev_readable, dev_sev_writable, has_crl_cache,
    has_reasonable_memlock_rlimit, kvm_version, sev_enabled_in_kernel, CPUIDS,
};

use std::io;
use std::sync::Arc;

use crate::backend::sev::data::has_vcek_cache;
use crate::backend::Signatures;
use anyhow::{bail, Context, Result};
use der::Encode;
use kvm_bindings::bindings::kvm_enc_region;
use kvm_ioctls::VmFd;
use sallyport::host::deref_slice;
use sallyport::item::enarxcall::Payload;
use sallyport::item::{self, Item};
use sallyport::libc::EMSGSIZE;

struct SnpKeepPersonality {
    // Must be kept open for the VM to talk to the SEV Firmware
    _sev_fd: Firmware,
}

impl KeepPersonality for SnpKeepPersonality {
    fn map(vm_fd: &mut VmFd, region: &Region, is_private: bool) -> io::Result<()> {
        let memory_region = kvm_enc_region {
            addr: region.backing().as_ptr() as _,
            size: region.backing().len() as _,
        };
        vm_fd
            .register_enc_memory_region(&memory_region)
            .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;

        if is_private {
            set_memory_attributes(
                vm_fd,
                region.as_guest().start.as_u64(),
                region.as_guest().count,
                true,
            )?;
        }

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
                const UPDATE_ERROR: &str = "Could not get SEV-SNP evidence! Run `enarx platform snp vcek update && enarx platform snp cache-crl`";

                let vcek_buf: &mut [u8] = unsafe {
                    // Safety: `deref_slice` gives us a pointer to a byte slice, which does not have to be aligned.
                    // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                    // is a subslice of.
                    &mut *deref_slice::<u8>(data, *vcek_offset, *vcek_len)
                        .map_err(io::Error::from_raw_os_error)
                        .context("snp::enarxcall deref")?
                };

                let evidence = SnpEvidence::read()
                    .context(UPDATE_ERROR)?
                    .to_vec()
                    .context("SnpEvidence.to_vec()")?;
                if *ret == 0 {
                    bail!(UPDATE_ERROR)
                }

                if evidence.len() > vcek_buf.len() {
                    *ret = -EMSGSIZE as usize
                } else {
                    *ret = evidence.len();
                    vcek_buf[..*ret].copy_from_slice(&evidence);
                }
                Ok(None)
            }
            _ => return Ok(Some(Item::Enarxcall(enarxcall, data))),
        }
    }
}

/// Indicate to KVM whether to map shared or private pages into the guest.
pub fn set_memory_attributes(
    vm_fd: &mut VmFd,
    guest_phys_addr: u64,
    memory_size: u64,
    private: bool,
) -> Result<(), std::io::Error> {
    // TODO: This should be part of `kvm_ioctls` once
    // `KVM_SET_MEMORY_ATTRIBUTES` lands in the mainline kernel.

    #[repr(C)]
    pub struct KvmSetMemoryAttributes {
        address: u64,
        size: u64,
        attributes: u64,
        flags: u64,
    }

    let mut attributes = KvmSetMemoryAttributes {
        address: guest_phys_addr,
        size: memory_size,
        attributes: u64::from(private) << 3,
        flags: 0,
    };

    const KVM_SET_MEMORY_ATTRIBUTES: Ioctl<WriteRead, &KvmSetMemoryAttributes> =
        unsafe { Group::new(0xAE).write_read::<KvmSetMemoryAttributes>(0xd3) };

    KVM_SET_MEMORY_ATTRIBUTES.ioctl(vm_fd, &mut attributes)?;

    assert!(attributes.size == 0);

    Ok(())
}

pub struct Backend;

impl super::Backend for Backend {
    #[inline]
    fn name(&self) -> &'static str {
        "sev"
    }

    #[inline]
    fn shim(&self) -> &'static [u8] {
        super::kvm::Backend.shim()
    }

    #[inline]
    fn have(&self) -> bool {
        self.data().iter().all(|x| x.pass)
    }

    fn data(&self) -> Vec<super::Datum> {
        let mut data = vec![dev_sev(), sev_enabled_in_kernel(), dev_kvm(), kvm_version()];
        data.extend(CPUIDS.iter().map(|c| c.into()));
        data
    }

    fn config(&self) -> Vec<super::Datum> {
        vec![
            dev_sev_readable(),
            dev_sev_writable(),
            has_reasonable_memlock_rlimit(),
            has_vcek_cache(),
            has_crl_cache().unwrap_or_else(|e| e),
        ]
    }

    #[inline]
    fn keep(
        &self,
        shim: &[u8],
        exec: &[u8],
        signatures: Option<Signatures>,
    ) -> Result<Arc<dyn super::Keep>> {
        builder::Builder::load(shim, exec, signatures)
    }

    #[inline]
    fn hash(&self, shim: &[u8], exec: &[u8]) -> Result<Vec<u8>> {
        hasher::Hasher::load(shim, exec, None)
    }
}
