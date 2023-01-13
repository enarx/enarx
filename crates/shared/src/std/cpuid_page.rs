// SPDX-License-Identifier: Apache-2.0

//! Structures and methods to handle the SEV-SNP CPUID page

use crate::no_std::cpuid_page::COUNT_MAX;
pub use crate::no_std::cpuid_page::{CpuidFunctionEntry, CpuidPage};
use std::fmt::{Display, Formatter};

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

/// Extension trait for CpuidPage
pub trait CpuIdStdExt {
    /// Add a new entry to the page
    fn add_entry(&mut self, entry: &CpuidFunctionEntry) -> Result<(), Error>;
}

impl CpuIdStdExt for CpuidPage {
    /// Add an entry
    fn add_entry(&mut self, entry: &CpuidFunctionEntry) -> Result<(), Error> {
        if self.entry.count as usize >= COUNT_MAX {
            return Err(Error::Full);
        }
        self.entry.functions[self.entry.count as usize] = *entry;
        self.entry.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::no_std::cpuid_page::CpuidFunctionEntry;
    use crate::no_std::cpuid_page::COUNT_MAX;

    #[test]
    fn test_cpuid_page_add_entry() {
        let mut page = CpuidPage::default();
        let entry = CpuidFunctionEntry::default();
        for _ in 0..COUNT_MAX {
            assert!(page.add_entry(&entry).is_ok());
        }
        let ret = page.add_entry(&entry);
        assert!(ret.is_err());
        assert_eq!(
            ret.unwrap_err().to_string(),
            "CpuidPage already contains the maximum number of entries"
        );
    }
}
