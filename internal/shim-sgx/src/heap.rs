// SPDX-License-Identifier: Apache-2.0

//! Allocate and deallocate memory on a Heap

use crate::{shim_address, ENARX_EXEC_END, ENCL_SIZE};

use core::ffi::{c_int, c_size_t};
use core::num::NonZeroUsize;
use core::ops::Range;
use core::slice::from_raw_parts_mut;

use mmledger::{Access, Ledger, Region};
use primordial::{Address, Offset, Page};
use sallyport::libc::{
    off_t, EACCES, EINVAL, ENOMEM, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE,
};
use sgx::page::{Class, Flags};
use spinning::{Lazy, RwLock};
use x86_64::addr::VirtAddr;
use x86_64::structures::paging::Page as PageAddr;

/// The keep heap
pub static HEAP: Lazy<RwLock<Heap<'_>>> = Lazy::new(|| unsafe {
    let shim_end = &ENARX_EXEC_END as *const _ as usize;
    RwLock::new(Heap::new(from_raw_parts_mut(
        shim_end as *mut Page,
        (shim_address() + ENCL_SIZE - shim_end) / Page::SIZE,
    )))
});

/// A heap
pub struct Heap<'a> {
    memory: &'a mut [Page],
    ledger: Ledger<511>,
    brk: Option<NonZeroUsize>,
    brk_max: Option<NonZeroUsize>,
}

impl<'a> Heap<'a> {
    /// Create a new heap backed by the passed block
    ///
    /// # Safety
    ///
    /// This function is unsafe because it expects the block to be mapped RWX.
    const unsafe fn new(memory: &'a mut [Page]) -> Self {
        let brk = None;
        let memory_len = Address::new(memory.len() * Page::SIZE);
        Self {
            memory,
            ledger: Ledger::new(Region::new(Address::new(0), memory_len)),
            brk,
            brk_max: brk,
        }
    }

    /// Get reference to the heap's memory.
    pub fn memory(&self) -> &[Page] {
        self.memory
    }

    /// Returns the range of the heap area
    pub fn range(&self) -> Range<*const Page> {
        self.memory().as_ptr_range()
    }

    fn offset(&self, addr: usize) -> Option<usize> {
        let base = self.memory().as_ptr() as usize;
        let ceil = base + self.memory().len() * Page::SIZE;

        if base <= addr {
            if addr < ceil {
                return Some(addr - base);
            } else {
                return Some(ceil - base);
            }
        }

        None
    }

    fn offset_page_down(&self, addr: usize) -> Option<usize> {
        let off = self.offset(addr)?;
        Some(off / Page::SIZE)
    }

    fn offset_page_up(&self, addr: usize) -> Option<usize> {
        self.offset_page_down(addr + Page::SIZE - 1)
    }

    fn pos(&self) -> usize {
        self.brk
            .map(|x| x.into())
            .unwrap_or(self.memory().as_ptr() as _)
    }

    fn pos_max(&self) -> usize {
        self.brk_max
            .map(|x| x.into())
            .unwrap_or(self.memory().as_ptr() as _)
    }

    fn mmap_augment(&mut self, addr: c_size_t, length: c_size_t) -> Result<usize, c_int> {
        static ZERO_PAGE: Page = Page::zeroed();
        let pages = (length + Page::SIZE - 1) / Page::SIZE;
        let secinfo = Class::Regular.info(Flags::READ | Flags::WRITE | Flags::EXECUTE);
        let zero = PageAddr::from_start_address(VirtAddr::new(ZERO_PAGE.as_ptr() as u64)).unwrap();
        for i in 0..pages {
            let addr =
                PageAddr::from_start_address(VirtAddr::new((addr + i * pages) as u64)).unwrap();
            if secinfo.accept_copy(addr, zero).is_err() {
                panic!();
            }
        }

        Ok(addr)
    }

    fn mmap_fixed(
        &mut self,
        addr: c_size_t,
        length: c_size_t,
        prot: c_int,
    ) -> Result<usize, c_int> {
        let prot = prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
        let start = self.memory().as_ptr() as usize;
        let end = start + self.memory.len() * Page::SIZE;

        assert!(length > 0);
        assert!(addr >= start);
        assert!((addr + length) <= end);

        let pages = (length + Page::SIZE - 1) / Page::SIZE;
        let region = Region::new(
            Address::new(addr - start),
            Address::new(addr - start) + Offset::from_items(pages),
        );

        if self
            .ledger
            .map(region, Access::from_bits_truncate(prot as usize))
            .is_err()
        {
            return Err(EACCES);
        }

        if cfg!(test) {
            Ok(addr)
        } else {
            self.mmap_augment(addr, length)
        }
    }

    /// Allocate heap memory to address `brk`
    pub fn brk(&mut self, brk: usize) -> usize {
        let max = self.offset_page_up(self.pos_max()).unwrap();
        let old = self.offset_page_up(self.pos()).unwrap();
        let new = match self.offset_page_up(brk) {
            Some(page) => page,
            None => return self.pos(),
        };
        if new > max {
            if self
                .mmap_fixed(
                    old * Page::SIZE + self.memory().as_ptr() as usize,
                    new * Page::SIZE - old,
                    PROT_READ | PROT_WRITE,
                )
                .is_err()
            {
                return self.pos();
            }

            self.brk = NonZeroUsize::new(brk);
            self.brk_max = NonZeroUsize::new(brk);

            return brk;
        }
        self.brk = NonZeroUsize::new(brk);
        brk
    }

    /// mmap memory from the heap
    pub fn mmap<T>(
        &mut self,
        addr: c_size_t,
        length: c_size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> Result<*mut T, c_int> {
        const RWX: c_int = PROT_READ | PROT_WRITE | PROT_EXEC;
        const PA: c_int = MAP_PRIVATE | MAP_ANONYMOUS;
        let prot = prot & !RWX;
        if addr != 0 || fd != -1 || offset != 0 || prot != 0 || flags != PA || length == 0 {
            return Err(EINVAL);
        }

        let length = Offset::from_items((length + Page::SIZE - 1) / Page::SIZE);
        if let Some(addr) = self.ledger.find_free_back(length) {
            self.mmap_fixed(
                self.memory().as_ptr() as usize + addr.as_ptr() as usize,
                length.bytes(),
                prot,
            )
            .map(|addr| addr as *mut T)
        } else {
            Err(ENOMEM)
        }
    }

    /// munmap memory from the heap
    pub fn munmap<T>(&mut self, addr: *const T, _length: usize) -> Result<(), c_int> {
        let addr = addr as usize;

        if addr % Page::SIZE != 0 {
            return Err(EINVAL);
        }

        let brk = self.offset_page_up(self.pos()).unwrap();

        let bot = match self.offset_page_down(addr) {
            Some(page) => page,
            None => return Err(EINVAL),
        };

        // TODO: Re-enable when trimming for SGX2 is implemented.
        #[cfg(test)]
        let top = match self.offset_page_up(addr + _length) {
            Some(page) => page,
            None => return Err(EINVAL),
        };

        if bot < brk {
            return Err(EINVAL);
        }

        // TODO: Re-enable when trimming for SGX2 is implemented.
        #[cfg(test)]
        self.ledger
            .unmap(Region::new(
                Address::new(bot * Page::SIZE),
                Address::new(top * Page::SIZE),
            ))
            .unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use const_default::ConstDefault;
    use core::ffi::c_void;
    use core::ptr::null_mut;

    const PROT: c_int = PROT_READ;
    const FLAGS: c_int = MAP_PRIVATE | MAP_ANONYMOUS;

    /// An allocated block of memory
    #[repr(C, align(4096))]
    struct Block<const N: usize>([Page; N]);

    impl<const N: usize> Block<N> {
        const fn new() -> Self {
            Self([Page::DEFAULT; N])
        }
    }

    trait HeapTestExt {
        fn is_allocated(&self, page: usize) -> bool;
    }

    impl<'a> HeapTestExt for Heap<'a> {
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
    fn mmap_munmap_oneshot() {
        let mut block = Block::<128>::new();
        let mut heap = unsafe { Heap::new(&mut block.0) };

        for pages in [128, 64] {
            let brk_page = heap.memory().len() - pages;
            let brk = heap.memory().as_ptr() as usize + brk_page * Page::SIZE;
            let ret = heap.brk(brk);
            assert_eq!(ret, brk);

            let steps = [
                (Page::SIZE, 1),
                (Page::SIZE / 2, 1),
                (Page::SIZE + Page::SIZE / 2, 2),
                (pages * Page::SIZE, pages),
            ];

            for (s, allocated) in steps {
                let addr = heap.mmap(0, s, PROT, FLAGS, -1, 0).unwrap();

                for page in brk_page..heap.memory().len() - allocated {
                    assert!(!heap.is_allocated(page));
                }
                for page in heap.memory().len() - allocated..heap.memory().len() {
                    assert!(heap.is_allocated(page));
                }

                heap.munmap::<c_void>(addr, s).unwrap();
            }

            // try to allocate memory whose size exceeds the total heap size
            let len = heap.memory().len() * Page::SIZE + 1;
            let ret = heap.mmap::<c_void>(0, len, PROT, FLAGS, -1, 0);
            assert_eq!(ret.unwrap_err(), ENOMEM);
        }
    }

    #[test]
    fn mmap_munmap_incremental() {
        let mut block = Block::<128>::new();
        let mut heap = unsafe { Heap::new(&mut block.0) };

        for pages in [128, 64] {
            let brk_page = heap.memory().len() - pages;
            let brk = heap.memory().as_ptr() as usize + brk_page * Page::SIZE;
            let ret = heap.brk(brk);
            assert_eq!(ret, brk);

            let steps = [Page::SIZE, Page::SIZE / 2];

            for size in steps {
                let mut addrs = [null_mut::<c_void>(); 128];

                for addr in addrs[brk_page..heap.memory().len()].iter_mut() {
                    *addr = heap.mmap(0, size, PROT, FLAGS, -1, 0).unwrap();
                }

                for page in brk_page..heap.memory().len() {
                    assert!(heap.is_allocated(page));
                }

                // try to allocate memory but no free pages
                let ret = heap.mmap::<c_void>(0, size, PROT, FLAGS, -1, 0);
                assert_eq!(ret.unwrap_err(), ENOMEM);

                for addr in addrs[brk_page..heap.memory().len()].iter() {
                    heap.munmap(*addr, size).unwrap();
                }

                for page in brk_page..heap.memory().len() {
                    assert!(!heap.is_allocated(page));
                }
            }
        }
    }
}
