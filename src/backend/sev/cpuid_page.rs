// SPDX-License-Identifier: Apache-2.0

//! Structures and methods to handle the SEV-SNP CPUID page

use anyhow::Context;
use kvm_bindings::bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
use kvm_bindings::fam_wrappers::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::Kvm;
use shared::std::cpuid_page::CpuIdStdExt as _;
use shared::std::cpuid_page::{CpuidFunctionEntry, CpuidPage};

/// Import all cpuid entry from a KVM vCPU
pub fn import_from_kvm(cpuid_page: &mut CpuidPage, kvm_fd: &mut Kvm) -> anyhow::Result<()> {
    let mut has_entries = false;

    let kvm_cpuid_entries = kvm_fd
        .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
        .context("Failed to get CPUID entries")?;

    for kvm_entry in kvm_cpuid_entries.as_slice() {
        // GET_CPUID2 returns bogus entries at the end with all zero set
        if kvm_entry.function == 0 && kvm_entry.index == 0 && has_entries {
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

        cpuid_page
            .add_entry(&snp_cpuid_entry)
            .context("Failed to add CPUID entry to the CPUID page")?;

        has_entries = true;
    }
    Ok(())
}
