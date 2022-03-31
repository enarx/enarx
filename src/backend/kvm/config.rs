// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use goblin::elf64::program_header::PT_LOAD;
use sallyport::elf::{self, pf::kvm::SALLYPORT};

pub struct Config {
    pub sallyport_block_size: usize,
}

impl super::super::Config for Config {
    type Flags = u32;

    fn flags(flags: u32) -> Self::Flags {
        flags
    }

    fn new(shim: &super::super::Binary<'_>, _exec: &super::super::Binary<'_>) -> Result<Self> {
        let sallyport_headers = shim.headers(PT_LOAD).filter(|p| p.p_flags & SALLYPORT != 0);

        if sallyport_headers.count() != 1 {
            anyhow::bail!("KVM shim must contain exactly one sallyport PT_LOAD segment.")
        }

        let sallyport_block_size =
            // Safety: converting 8 bytes into u64 should not produce any unsound behavior.
            unsafe { shim.note::<u64>(elf::note::NAME, elf::note::BLOCK_SIZE) }
                .ok_or_else(|| anyhow!("KVM shim is missing BLOCK_SIZE"))? as usize;

        Ok(Self {
            sallyport_block_size,
        })
    }
}
