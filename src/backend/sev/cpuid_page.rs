// SPDX-License-Identifier: Apache-2.0

//! Structures and methods to handle the SEV-SNP CPUID page

use const_default::ConstDefault;

use core::fmt::{Debug, Formatter};
use core::mem::size_of;
use std::fmt::Display;

use anyhow::Context;
use kvm_bindings::bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
use kvm_bindings::fam_wrappers::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::Kvm;

const COUNT_MAX: usize = 64;

/// An entry in the SNP CPUID Page
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, ConstDefault, Eq, PartialEq)]
pub struct CpuidFunctionEntry {
    /// function
    pub eax_in: u32,
    /// index
    pub ecx_in: u32,
    /// register state when cpuid is called
    pub xcr0_in: u64,
    /// register state when cpuid is called
    pub xss_in: u64,
    /// cpuid out
    pub eax: u32,
    /// cpuid out
    pub ebx: u32,
    /// cpuid out
    pub ecx: u32,
    /// cpuid out
    pub edx: u32,
    reserved: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct CpuidPageEntry {
    count: u32,
    reserved_1: u32,
    reserved_2: u64,
    functions: [CpuidFunctionEntry; COUNT_MAX],
}

impl ConstDefault for CpuidPageEntry {
    const DEFAULT: Self = CpuidPageEntry {
        count: 0,
        reserved_1: 0,
        reserved_2: 0,
        functions: [<CpuidFunctionEntry as ConstDefault>::DEFAULT; COUNT_MAX],
    };
}

impl Default for CpuidPageEntry {
    fn default() -> Self {
        <Self as ConstDefault>::DEFAULT
    }
}

/// The CPUID page to be copied in the guest VM
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CpuidPage {
    entry: CpuidPageEntry,
    space: [u8; CpuidPage::space_size()],
}

impl CpuidPage {
    const fn space_size() -> usize {
        4096 - size_of::<CpuidPageEntry>()
    }
}

impl ConstDefault for CpuidPage {
    const DEFAULT: Self = CpuidPage {
        entry: ConstDefault::DEFAULT,
        space: [0; CpuidPage::space_size()],
    };
}

impl Default for CpuidPage {
    fn default() -> Self {
        <Self as ConstDefault>::DEFAULT
    }
}

/// Error thrown by CpuidPage methods
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// the page already contains the maximum number of entries
    Full,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CpuidPage already contains the maximum number of entries"
        )
    }
}

impl std::error::Error for Error {}

impl CpuidPage {
    /// Add an entry
    pub fn add_entry(&mut self, entry: &CpuidFunctionEntry) -> Result<(), Error> {
        if self.entry.count as usize >= COUNT_MAX {
            return Err(Error::Full);
        }
        self.entry.functions[self.entry.count as usize] = *entry;
        self.entry.count += 1;
        Ok(())
    }

    /// Import all cpuid entry from a KVM vCPU
    pub fn import_from_kvm(&mut self, kvm_fd: &mut Kvm) -> anyhow::Result<()> {
        let kvm_cpuid_entries = kvm_fd
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .context("Failed to get CPUID entries")?;

        for kvm_entry in kvm_cpuid_entries.as_slice() {
            // GET_CPUID2 returns bogus entries at the end with all zero set
            if kvm_entry.function == 0 && kvm_entry.index == 0 && (self.entry.count > 0) {
                break;
            }

            if kvm_entry.function == 0xFFFFFFFF {
                break;
            }

            // range check, see:
            // SEV Secure Nested Paging Firmware ABI Specification
            // 8.14.2.6 PAGE_TYPE_CPUID
            if !((0..0xFFFF).contains(&kvm_entry.function)
                || (0x8000_0000..0x8000_FFFF).contains(&kvm_entry.function))
            {
                continue;
            }

            let mut snp_cpuid_entry = CpuidFunctionEntry {
                eax_in: kvm_entry.function,
                ecx_in: {
                    if (kvm_entry.flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) != 0 {
                        kvm_entry.index
                    } else {
                        0
                    }
                },
                xcr0_in: 0,
                xss_in: 0,
                eax: kvm_entry.eax,
                ebx: kvm_entry.ebx,
                ecx: kvm_entry.ecx,
                edx: kvm_entry.edx,
                ..Default::default()
            };

            if snp_cpuid_entry.eax_in == 0xD
                && (snp_cpuid_entry.ecx_in == 0x0 || snp_cpuid_entry.ecx_in == 0x1)
            {
                // Workaround copied from https://github.com/AMDESE/qemu/commit/9ad35600356a2fe1bb1aea6d5f95ea86d205b25d

                // The value returned in EBX gives the save area size requirement in bytes based on the features
                // currently enabled in the XFEATURE_ENABLED_MASK (XCR0).

                snp_cpuid_entry.ebx = 0x240;
            }

            self.add_entry(&snp_cpuid_entry)
                .context("Failed to add CPUID entry to the CPUID page")?;
        }
        Ok(())
    }
}
