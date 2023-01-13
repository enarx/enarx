// SPDX-License-Identifier: Apache-2.0

//! Structures and methods to handle the SEV-SNP CPUID page

use const_default::ConstDefault;
use core::mem::size_of;

pub(crate) const COUNT_MAX: usize = 64;

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
    /// reserved, must be zero
    pub reserved: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub(crate) struct CpuidPageEntry {
    pub(crate) count: u32,
    reserved_1: u32,
    reserved_2: u64,
    pub(crate) functions: [CpuidFunctionEntry; COUNT_MAX],
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
    pub(crate) entry: CpuidPageEntry,
    space: [u8; CpuidPage::space_size()],
}

impl CpuidPage {
    #[allow(clippy::integer_arithmetic)]
    const fn space_size() -> usize {
        4096 - size_of::<CpuidPageEntry>()
    }

    /// Get all entries
    #[inline]
    pub fn get_functions(&self) -> &[CpuidFunctionEntry] {
        &self.entry.functions[..self.entry.count as usize]
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cpuid_page_size() {
        assert_eq!(size_of::<CpuidPage>(), 4096);
    }

    #[test]
    fn test_cpuid_page_entry_size() {
        assert_eq!(CpuidPage::space_size(), 1008);
    }

    #[test]
    fn test_get_functions() {
        let mut page = CpuidPage::default();
        let entry = CpuidFunctionEntry::default();
        page.entry.functions[0] = entry;
        page.entry.count = 1;
        assert_eq!(page.get_functions(), &[entry]);
    }
}
