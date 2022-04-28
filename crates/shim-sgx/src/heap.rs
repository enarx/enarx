// SPDX-License-Identifier: Apache-2.0

//! Allocate and deallocate memory on a Heap

use mmledger::{Access, Ledger, Region};
use primordial::{Address, Offset, Page};

/// A heap
pub struct Heap {
    start: Address<usize, Page>,
    end: Address<usize, Page>,
    brk: Address<usize, Page>,
    brk_max: Address<usize, Page>,
    ledger: Ledger<4094>,
}

impl Heap {
    /// Create a new instance.
    pub const fn new(start: Address<usize, Page>, end: Address<usize, Page>) -> Self {
        let region = Region::new(start, end);
        Self {
            start,
            end,
            brk: start,
            brk_max: start,
            ledger: Ledger::new(region),
        }
    }

    /// Check whether the heap contains the given region, and return the
    /// maximum allowed access for it.
    pub fn contains(&self, region: Region) -> Option<Access> {
        self.ledger.contains(region)
    }

    /// Return the maximum `brk` address reached.
    pub fn brk_max(&self) -> Address<usize, Page> {
        self.brk_max
    }

    /// Increase or decrease `brk` address.
    pub fn brk(&mut self, brk: Address<usize, Page>) -> Address<usize, Page> {
        if brk < self.start || brk >= self.end {
            return self.brk;
        }

        if brk <= self.brk_max {
            self.brk = brk;
            return brk;
        }

        let region = Region::new(self.brk_max, brk);

        if self.ledger.overlaps(region) {
            return self.brk;
        }

        if self
            .ledger
            .map(region, Access::READ | Access::WRITE)
            .is_err()
        {
            return self.brk;
        }

        self.brk_max = brk;
        brk
    }

    /// Find and reserve an address range.
    pub fn mmap(
        &mut self,
        addr: Option<Address<usize, Page>>,
        length: Offset<usize, Page>,
        access: Access,
    ) -> Option<Address<usize, Page>> {
        let addr = match addr {
            None => self.ledger.find_free_back(length)?,
            Some(addr) => addr,
        };
        let region = Region::new(addr, addr + length);
        self.ledger.map(region, access).ok()?;
        Some(addr)
    }

    /// Release a region.
    pub fn munmap(&mut self, region: Region) {
        self.ledger.unmap(region).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGES: usize = 128;
    const BYTES: usize = PAGES * Page::SIZE;

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
        let mut heap = Heap::new(Address::new(0), Address::new(BYTES));

        for pages in [128, 64] {
            let brk_page = PAGES - pages;
            let brk = Address::new(brk_page * Page::SIZE);

            let steps = [1, pages];

            for allocated in steps {
                assert_ne!(
                    heap.mmap(None, Offset::from_items(allocated), Access::READ),
                    None
                );

                let ret = heap.brk(brk);
                assert_eq!(ret, brk);

                for page in brk_page..PAGES - allocated {
                    assert!(!heap.is_allocated(page));
                }
                for page in PAGES - allocated..PAGES {
                    assert!(heap.is_allocated(page));
                }

                heap.munmap(Region::new(
                    Address::new((PAGES - allocated) * Page::SIZE),
                    Address::new(BYTES),
                ));
            }
        }
    }

    #[test]
    fn mmap_oversubscribe() {
        let mut heap = Heap::new(Address::new(0), Address::new(BYTES));
        assert_eq!(
            heap.mmap(None, Offset::from_items(BYTES + Page::SIZE), Access::READ),
            None
        );
    }
}
