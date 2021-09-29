// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use goblin::elf64::program_header::PT_LOAD;
use sallyport::elf::pf::kvm::SALLYPORT;

pub struct Config {}

impl super::super::Config for Config {
    type Flags = u32;

    fn flags(flags: u32) -> Self::Flags {
        flags
    }

    fn new(shim: &super::super::Binary, _exec: &super::super::Binary) -> Result<Self> {
        let sallyport_headers = shim.headers(PT_LOAD).filter(|p| p.p_flags & SALLYPORT != 0);

        if sallyport_headers.count() != 1 {
            anyhow::bail!("KVM shim must contain exactly one sallyport PT_LOAD segment.")
        }

        Ok(Self {})
    }
}
