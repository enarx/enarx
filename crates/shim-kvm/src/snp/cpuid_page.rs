// SPDX-License-Identifier: Apache-2.0

//! Structures and methods to handle the SEV-SNP CPUID page

use core::arch::x86_64::CpuidResult;

use crate::snp::snp_active;
use crate::_ENARX_CPUID;

/// See [`cpuid_count`](cpuid_count).
#[inline]
pub fn cpuid(leaf: u32) -> CpuidResult {
    cpuid_count(leaf, 0)
}

/// Returns the result of the `cpuid` instruction for a given `leaf` (`EAX`)
/// and `sub_leaf` (`ECX`).
///
/// If in SEV-SNP mode this function will lookup the return values in the CPUID page.
///
/// In case of leaf 1, the osxsave feature bit will be set, if the xsave feature bit is set.
///
/// The highest-supported leaf value is returned by the first tuple argument of
/// [`__get_cpuid_max(0)`](fn.__get_cpuid_max.html). For leaves containung
/// sub-leaves, the second tuple argument returns the highest-supported
/// sub-leaf
/// value.
///
/// The [CPUID Wikipedia page][wiki_cpuid] contains how to query which
/// information using the `EAX` and `ECX` registers, and the interpretation of
/// the results returned in `EAX`, `EBX`, `ECX`, and `EDX`.
///
/// The references are:
/// - [Intel 64 and IA-32 Architectures Software Developer's Manual Volume 2:
///   Instruction Set Reference, A-Z][intel64_ref].
/// - [AMD64 Architecture Programmer's Manual, Volume 3: General-Purpose and
///   System Instructions][amd64_ref].
///
/// [wiki_cpuid]: https://en.wikipedia.org/wiki/CPUID
/// [intel64_ref]: http://www.intel.de/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
/// [amd64_ref]: http://support.amd.com/TechDocs/24594.pdf
#[inline]
pub fn cpuid_count(leaf: u32, sub_leaf: u32) -> CpuidResult {
    let mut res = if snp_active() {
        let cpuid = &unsafe { _ENARX_CPUID };
        cpuid
            .get_functions()
            .iter()
            .find_map(|e| {
                if e.eax_in == leaf && e.ecx_in == sub_leaf {
                    Some(CpuidResult {
                        eax: e.eax,
                        ebx: e.ebx,
                        ecx: e.ecx,
                        edx: e.edx,
                    })
                } else {
                    None
                }
            })
            .unwrap_or(CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            })
    } else {
        unsafe { core::arch::x86_64::__cpuid_count(leaf, sub_leaf) }
    };

    if leaf == 1 && sub_leaf == 0 && (res.ecx & (1u32 << 26)) != 0 {
        // set osxsave feature bit, if xsave feature bit is set
        res.ecx |= 1u32 << 27;
    }

    res
}

/// Returns the highest-supported `leaf` (`EAX`) and sub-leaf (`ECX`) `cpuid`
/// values.
///
/// If `cpuid` is supported, and `leaf` is zero, then the first tuple argument
/// contains the highest `leaf` value that `cpuid` supports. For `leaf`s
/// containing sub-leafs, the second tuple argument contains the
/// highest-supported sub-leaf value.
///
/// See also [`cpuid`](cpuid) and
/// [`cpuid_count`](cpuid_count).
#[inline]
pub fn get_cpuid_max(leaf: u32) -> (u32, u32) {
    let CpuidResult { eax, ebx, .. } = cpuid(leaf);
    (eax, ebx)
}
