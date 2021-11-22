// SPDX-License-Identifier: Apache-2.0

//! FIXME: move to sev crate

use core::arch::x86_64::CpuidResult;
use core::fmt::Debug;
use core::mem::size_of;

use const_default::ConstDefault;

use crate::snp::snp_active;
use crate::_ENARX_CPUID;

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
    #[allow(clippy::integer_arithmetic)]
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
    /// no memory allocating structs for the ioctl
    NoMemory,
    /// the page already contains the maximum number of entries
    Full,
}

impl CpuidPage {
    /// Get all entries
    #[inline]
    pub fn get_functions(&self) -> &[CpuidFunctionEntry] {
        &self.entry.functions[..self.entry.count as usize]
    }
}

/// See [`cpuid_count`](cpuid_count).
#[inline]
pub fn cpuid(leaf: u32) -> CpuidResult {
    cpuid_count(leaf, 0)
}

/// Returns the result of the `cpuid` instruction for a given `leaf` (`EAX`)
/// and
/// `sub_leaf` (`ECX`).
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
    if !snp_active() {
        unsafe { core::arch::x86_64::__cpuid_count(leaf, sub_leaf) }
    } else {
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
    }
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
