// SPDX-License-Identifier: Apache-2.0

use crate::backend::kvm::{self, measure};

use sev::firmware::Firmware;
use sev::launch::Launcher;

use ciborium::{de::from_reader, ser::into_writer};
use koine::attestation::sev::*;
use kvm_ioctls::VmFd;
use x86_64::{PhysAddr, VirtAddr};

use crate::binary::{Component, PT_ENARX_PML4};
use anyhow::{Context, Result};
use std::convert::TryFrom;
use std::os::unix::net::UnixStream;
use x86_64::structures::paging::PageTable;

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

    fn shim_loaded(
        &mut self,
        _vm: &mut VmFd,
        addr_space: &mut [u8],
        shim: &Component,
    ) -> Result<()> {
        // The initial page tables of the shim must be corrected
        // with the current CPU's C-bit indicating encrypted memory.

        // query the C-bit location via cpuid
        use core::arch::x86_64::__cpuid_count;
        let c_bit_loc = unsafe { __cpuid_count(0x8000_001f, 0x0000_0000) }.ebx;
        let c_bit_loc = c_bit_loc & 0x3f;
        let c_bit_mask = 1u64 << c_bit_loc;

        // locate the page tables of the shim via the ELF program headers
        let pml4 = shim
            .find_header(PT_ENARX_PML4)
            .ok_or_else(|| {
                anyhow::anyhow!("Couldn't find PML4 program header in shim executable.")
            })?
            .vm_range()
            .start;

        let shim_start = shim.region().start;

        let addr_space = addr_space.as_mut_ptr();
        let host_pml4 = unsafe { addr_space.add(pml4 - shim_start) };

        // The top level page table
        let pagetable: &mut PageTable = unsafe { &mut *(host_pml4 as *mut PageTable) };

        for entry in pagetable.iter_mut().filter(|x| !x.is_unused()) {
            let host_addr = unsafe { addr_space.add(entry.addr().as_u64() as usize - shim_start) };

            let pdpt_pagetable: &mut PageTable = unsafe { &mut *(host_addr as *mut PageTable) };

            unsafe {
                entry.set_addr(
                    PhysAddr::new_unsafe(entry.addr().as_u64() | c_bit_mask),
                    entry.flags(),
                );
            }

            // Also correct the next level
            for entry in pdpt_pagetable.iter_mut().filter(|x| !x.is_unused()) {
                unsafe {
                    entry.set_addr(
                        PhysAddr::new_unsafe(entry.addr().as_u64() | c_bit_mask),
                        entry.flags(),
                    );
                }
            }
        }

        Ok(())
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
