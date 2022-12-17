// SPDX-License-Identifier: Apache-2.0

//! Allocate and deallocate memory on a Heap

use const_default::ConstDefault;
use core::fmt;

use mmledger::{Ledger, LedgerAccess, Record, Region};
use primordial::{Address, Offset, Page};

bitflags::bitflags! {
    /// Memory access permissions.
    #[derive(Default)]
    #[repr(transparent)]
    pub struct Access: usize {
        /// Read access
        const READ = 1 << 0;

        /// Write access
        const WRITE = 1 << 1;

        /// Execute access
        const EXECUTE = 1 << 2;

        /// Memory was allocated by the shim
        const MMAPPED = 1 << 3;
    }
}

impl ConstDefault for Access {
    const DEFAULT: Self = Self::empty();
}

impl LedgerAccess for Access {
    const ALL: Self = Self::all();
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.contains(Access::READ) {
                'r'
            } else {
                '-'
            },
            if self.contains(Access::WRITE) {
                'w'
            } else {
                '-'
            },
            if self.contains(Access::EXECUTE) {
                'x'
            } else {
                '-'
            },
            if self.contains(Access::MMAPPED) {
                'x'
            } else {
                '-'
            }
        )
    }
}

/// A heap
#[derive(Debug)]
pub struct Heap {
    brk: Address<usize, Page>,
    brk_region: Region,
    // FIXME: use a dynamic Ledger
    // https://github.com/enarx/enarx/issues/2264
    ledger: Ledger<Access, 8188>,
}

impl Heap {
    /// Create a new instance.
    pub fn new(addr: Address<usize, Page>, length: Offset<usize, Page>) -> Self {
        Self {
            brk: addr,
            brk_region: Region::new(addr, addr),
            ledger: Ledger::new(addr, length),
        }
    }

    /// Check whether the heap contains the given region, and return the
    /// maximum allowed access for it.
    pub fn contains(
        &self,
        addr: Address<usize, Page>,
        length: Offset<usize, Page>,
    ) -> Option<Access> {
        self.ledger.contains(addr, length)
    }

    /// Return the maximum `brk` address reached.
    pub fn brk_max(&self) -> Address<usize, Page> {
        self.brk_region.end
    }

    /// Increase or decrease `brk` address.
    pub fn brk(&mut self, next: Address<usize, Page>) -> Address<usize, Page> {
        if !self.ledger.valid(next, Offset::from_items(1)) {
            return self.brk;
        }

        if next >= self.brk_region.start && next <= self.brk_region.end {
            self.brk = next;
            return next;
        }

        let length = next - self.brk_region.end;

        if self.ledger.overlaps(self.brk_region.end, length) {
            return self.brk;
        }

        match self.ledger.map(
            self.brk_region.end,
            length,
            Access::READ | Access::WRITE | Access::MMAPPED,
        ) {
            Ok(_) => {
                self.brk_region.end = next;
                next
            }
            Err(_) => self.brk,
        }
    }

    /// Find and reserve an address range.
    pub fn mmap(
        &mut self,
        addr: Option<Address<usize, Page>>,
        length: Offset<usize, Page>,
        access: Access,
    ) -> Option<Address<usize, Page>> {
        let addr = addr.or_else(|| self.ledger.find_free_back(length))?;
        self.ledger.map(addr, length, access).ok()?;
        Some(addr)
    }

    /// Change access permissions of an address range.
    pub fn protect_with(
        &mut self,
        addr: Address<usize, Page>,
        length: Offset<usize, Page>,
        func: impl FnMut(&Record<Access>) -> Access,
    ) -> Result<(), mmledger::Error> {
        self.ledger.protect_with(addr, length, func)
    }

    /// Release a region.
    pub fn munmap(
        &mut self,
        addr: Address<usize, Page>,
        length: Offset<usize, Page>,
    ) -> Result<(), mmledger::Error> {
        self.ledger.unmap(addr, length)
    }

    /// Release a region.
    pub fn munmap_with(
        &mut self,
        addr: Address<usize, Page>,
        length: Offset<usize, Page>,
        func: impl FnMut(&Record<Access>),
    ) -> Result<(), mmledger::Error> {
        self.ledger.unmap_with(addr, length, func)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGES: usize = 128;

    trait HeapTestExt {
        fn is_allocated(&self, page: usize) -> bool;
    }

    impl HeapTestExt for Heap {
        fn is_allocated(&self, page: usize) -> bool {
            let addr = page * Page::SIZE;
            for record in self.ledger.records() {
                let record_start = record.region.start.as_ptr() as usize;
                let record_end = record.region.end.as_ptr() as usize;
                if addr >= record_start && addr < record_end {
                    return true;
                }
            }
            false
        }
    }

    #[test]
    fn mmap_order() {
        let mut heap = Heap::new(Address::new(0), Offset::from_items(PAGES));

        for pages in [128, 64] {
            let brk_page = PAGES - pages;
            let brk = Address::new(brk_page * Page::SIZE);

            let steps = [1, pages];

            for allocated in steps {
                let ret = heap.mmap(None, Offset::from_items(allocated), Access::READ);
                assert_ne!(ret, None);

                let ret = heap.brk(brk);
                assert_eq!(ret, brk);

                for page in brk_page..PAGES - allocated {
                    assert!(!heap.is_allocated(page));
                }
                for page in PAGES - allocated..PAGES {
                    assert!(heap.is_allocated(page));
                }

                heap.munmap(
                    Address::new((PAGES - allocated) * Page::SIZE),
                    Offset::from_items(PAGES),
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn mmap_oversubscribe() {
        let mut heap = Heap::new(Address::new(0), Offset::from_items(PAGES));
        assert_eq!(
            heap.mmap(None, Offset::from_items(PAGES + 1), Access::READ),
            None
        );
    }
}
