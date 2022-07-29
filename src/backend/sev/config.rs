// SPDX-License-Identifier: Apache-2.0

use super::snp::Parameters;
use crate::backend::sev::snp::launch::IdBlock;
use crate::backend::Signatures;
use anyhow::{anyhow, Result};
use goblin::elf64::program_header::PT_LOAD;
use sallyport::elf::{self, pf::kvm::SALLYPORT};

pub struct Config {
    pub sallyport_block_size: usize,
    pub signatures: Option<Signatures>,
    pub parameters: Parameters,
}

impl Config {
    pub(crate) fn id_block_from_digest(&self, digest: [u8; 48]) -> IdBlock {
        IdBlock {
            launch_digest: digest,
            family_id: self.parameters.family_id,
            image_id: self.parameters.image_id,
            guest_svn: self.parameters.guest_svn,
            policy: self.parameters.policy,
            ..Default::default()
        }
    }
}

impl super::super::Config for Config {
    type Flags = u32;

    fn flags(flags: u32) -> Self::Flags {
        flags
    }

    fn new(
        shim: &super::super::Binary<'_>,
        _exec: &super::super::Binary<'_>,
        signatures: Option<Signatures>,
    ) -> Result<Self> {
        let sallyport_headers = shim.headers(PT_LOAD).filter(|p| p.p_flags & SALLYPORT != 0);

        if sallyport_headers.count() != 1 {
            anyhow::bail!("KVM shim must contain exactly one sallyport PT_LOAD segment.")
        }

        let sallyport_block_size =
            // Safety: converting 8 bytes into u64 should not produce any unsound behavior.
            unsafe { shim.note::<u64>(elf::note::NAME, elf::note::BLOCK_SIZE) }
                .ok_or_else(|| anyhow!("KVM shim is missing BLOCK_SIZE"))? as usize;

        let parameters: Parameters = unsafe {
            Parameters {
                policy: shim
                    .note(elf::note::NAME, elf::note::snp::POLICY)
                    .ok_or_else(|| anyhow!("KVM shim is missing POLICY"))?,
                family_id: shim
                    .note(elf::note::NAME, elf::note::snp::FAMILY_ID)
                    .ok_or_else(|| anyhow!("KVM shim is missing FAMILY_ID"))?,
                image_id: shim
                    .note(elf::note::NAME, elf::note::snp::IMAGE_ID)
                    .ok_or_else(|| anyhow!("KVM shim is missing IMAGE_ID"))?,
                guest_svn: shim
                    .note(elf::note::NAME, elf::note::snp::SVN)
                    .ok_or_else(|| anyhow!("KVM shim is missing GUEST_SVN"))?,
            }
        };

        Ok(Self {
            sallyport_block_size,
            signatures,
            parameters,
        })
    }
}
