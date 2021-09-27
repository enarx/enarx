// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroU32;

use anyhow::{anyhow, Result};
use goblin::elf::program_header::{PF_R, PF_W, PF_X};
use sallyport::elf;
use sgx::page::{Flags, SecInfo};
use sgx::parameters::{Masked, Parameters};

pub struct Config {
    pub parameters: Parameters,
    pub ssap: NonZeroU32,
    pub size: usize,
}

impl super::super::Config for Config {
    type Flags = (SecInfo, bool);

    fn flags(flags: u32) -> Self::Flags {
        let mut rwx = Flags::empty();
        if flags & PF_R != 0 {
            rwx |= Flags::READ;
        }
        if flags & PF_W != 0 {
            rwx |= Flags::WRITE;
        }
        if flags & PF_X != 0 {
            rwx |= Flags::EXECUTE;
        }

        let m = flags & elf::pf::sgx::UNMEASURED == 0;
        let si = match flags & elf::pf::sgx::TCS {
            0 => SecInfo::reg(rwx),
            _ => SecInfo::tcs(),
        };

        (si, m)
    }

    fn new(shim: &super::super::Binary, _exec: &super::super::Binary) -> Result<Self> {
        unsafe {
            let params: Parameters = Parameters {
                misc: Masked {
                    data: shim
                        .note(elf::note::NAME, elf::note::sgx::MISC)
                        .ok_or_else(|| anyhow!("SGX shim is missing MISC"))?,
                    mask: shim
                        .note(elf::note::NAME, elf::note::sgx::MISCMASK)
                        .ok_or_else(|| anyhow!("SGX shim is missing MISCMASK"))?,
                },
                attr: Masked {
                    data: shim
                        .note(elf::note::NAME, elf::note::sgx::ATTR)
                        .ok_or_else(|| anyhow!("SGX shim is missing ATTR"))?,
                    mask: shim
                        .note(elf::note::NAME, elf::note::sgx::ATTRMASK)
                        .ok_or_else(|| anyhow!("SGX shim is missing ATTRMASK"))?,
                },
                pid: shim
                    .note(elf::note::NAME, elf::note::sgx::PID)
                    .ok_or_else(|| anyhow!("SGX shim is missing PID"))?,
                svn: shim
                    .note(elf::note::NAME, elf::note::sgx::SVN)
                    .ok_or_else(|| anyhow!("SGX shim is missing SVN"))?,
            };

            let ssap: u8 = shim
                .note(elf::note::NAME, elf::note::sgx::SSAP)
                .ok_or_else(|| anyhow!("SGX shim is missing SSAP"))?;
            let ssap =
                NonZeroU32::new(ssap.into()).ok_or_else(|| anyhow!("SGX shim SSAP is invalid"))?;

            let bits: u8 = shim
                .note(elf::note::NAME, elf::note::sgx::BITS)
                .ok_or_else(|| anyhow!("SGX shim is missing BITS"))?;

            Ok(Self {
                parameters: params,
                size: 1 << bits,
                ssap,
            })
        }
    }
}
