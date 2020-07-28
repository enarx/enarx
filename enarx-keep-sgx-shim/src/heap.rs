// SPDX-License-Identifier: Apache-2.0

use core::mem::size_of;
use core::slice::from_raw_parts_mut as slice;

use bounds::{Line, Span};
use memory::Page;

type Word = usize;

struct Metadata {
    brk: Line<usize>,
}

pub struct Heap {
    metadata: &'static mut Metadata,
    allocated: &'static mut [Word],
    pages: &'static mut [Page],
}

impl Heap {
    pub unsafe fn new(heap: Span<usize>) -> Self {
        // Bits per page
        const BPP: usize = Page::size() * 8;

        // A page-aligned heap
        let heap = slice(heap.start as *mut u8, heap.count as _)
            .align_to_mut::<Page>()
            .1;

        // Reserve the first page for metadata
        let (metadata, heap) = heap.split_at_mut(1);
        let metadata: &mut Metadata = &mut metadata.align_to_mut().1[0];

        // Reserve the next n pages for the allocation map
        let (allocated, pages) = heap.split_at_mut((heap.len() + BPP - 1) / BPP);
        let allocated = allocated.align_to_mut().1;

        // Initialize brk.
        if metadata.brk.start == 0 {
            metadata.brk.start = pages.as_ptr() as _;
            metadata.brk.end = pages.as_ptr() as _;
        }

        // Remaining pages are usable memory
        Self {
            metadata,
            allocated,
            pages,
        }
    }

    const fn idx_bit(page: usize) -> (usize, usize) {
        let idx = page / (size_of::<Word>() * 8);
        let bit = page % (size_of::<Word>() * 8);
        (idx, bit)
    }

    fn is_allocated(&self, page: usize) -> bool {
        let (idx, bit) = Self::idx_bit(page);
        self.allocated[idx] & (1 << bit) != 0
    }

    fn is_allocated_range(&self, range: core::ops::Range<usize>) -> bool {
        for i in range {
            if self.is_allocated(i) {
                return true;
            }
        }

        false
    }

    fn allocate(&mut self, page: usize) {
        let (idx, bit) = Self::idx_bit(page);
        self.allocated[idx] |= 1 << bit;
    }

    fn deallocate(&mut self, page: usize) {
        let (idx, bit) = Self::idx_bit(page);
        self.allocated[idx] &= !(1 << bit);
    }

    fn offset(&self, addr: usize) -> Option<usize> {
        let base = self.pages.as_ptr() as usize;
        let ceil = base + self.pages.len() * Page::size();

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
        Some(off / Page::size())
    }

    fn offset_page_up(&self, addr: usize) -> Option<usize> {
        self.offset_page_down(addr + Page::size() - 1)
    }

    pub fn brk(&mut self, brk: usize) -> usize {
        let old = self.offset_page_up(self.metadata.brk.end).unwrap();
        let new = match self.offset_page_up(brk) {
            Some(page) => page,
            None => return self.metadata.brk.end,
        };

        if old < new {
            for page in old..new {
                if self.is_allocated(page) {
                    return self.metadata.brk.end;
                }
            }

            for page in old..new {
                self.allocate(page);
            }
        } else {
            for page in old..new {
                self.deallocate(page);
            }
        }

        self.metadata.brk.end = brk;
        brk
    }

    pub fn mmap<T>(
        &mut self,
        addr: libc::size_t,
        length: libc::size_t,
        prot: libc::c_int,
        flags: libc::c_int,
        fd: libc::c_int,
        offset: libc::off_t,
    ) -> Result<*mut T, libc::c_int> {
        const RWX: libc::c_int = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        const PA: libc::c_int = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

        let prot = prot & !RWX;
        if addr != 0 || fd != -1 || offset != 0 || prot != 0 || flags != PA {
            return Err(libc::EINVAL);
        }

        // The number of pages we need for the given length.
        let pages = (length + Page::size() - 1) / Page::size();

        // Find the brk page offset.
        let brk = self.offset_page_up(self.metadata.brk.end).unwrap();

        let end = match self.pages.len().checked_sub(pages) {
            Some(end) => end,
            None => return Err(libc::ENOMEM),
        };

        // Search for pages from the end to the front.
        for i in (brk..=end).rev() {
            let range = i..i + pages;

            if !self.is_allocated_range(range.clone()) {
                for page in range.clone() {
                    self.allocate(page);
                }

                return Ok(self.pages[range].as_mut_ptr() as *mut T);
            }
        }

        Err(libc::ENOMEM)
    }

    pub fn munmap<T>(&mut self, addr: *const T, length: usize) -> Result<(), libc::c_int> {
        let addr = addr as usize;

        if addr % Page::size() != 0 {
            return Err(libc::EINVAL);
        }

        let brk = self.offset_page_up(self.metadata.brk.end).unwrap();

        let bot = match self.offset_page_down(addr) {
            Some(page) => page,
            None => return Err(libc::EINVAL),
        };

        let top = match self.offset_page_up(addr + length) {
            Some(page) => page,
            None => return Err(libc::EINVAL),
        };

        if bot < brk {
            return Err(libc::EINVAL);
        }

        for page in bot..top {
            self.deallocate(page);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;
    use libc::c_void;

    const PROT: libc::c_int = libc::PROT_READ;
    const FLAGS: libc::c_int = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    const NUM_PAGES: usize = 10;

    fn new_checked(bytes: &mut [u8]) -> Heap {
        let aligned = unsafe { bytes.align_to_mut::<Page>().1 };
        let span = Span {
            start: aligned.as_mut_ptr() as _,
            count: (aligned.len() * Page::size()) as _,
        };
        let heap = unsafe { Heap::new(span) };

        // brk points to the first page
        assert_eq!(heap.metadata.brk.start, heap.pages.as_ptr() as _);
        assert_eq!(heap.metadata.brk.end, heap.pages.as_ptr() as _);

        // exclude 2 pages for metadata and allocation map
        assert_eq!(heap.pages.len(), aligned.len() - 2);

        // no pages are allocated
        for page in 0..heap.pages.len() {
            assert!(!heap.is_allocated(page));
        }

        heap
    }

    fn oneshot(heap: &mut Heap, pages: usize) {
        let brk_page = heap.pages.len() - pages;
        let brk = heap.metadata.brk.start + brk_page * Page::size();
        let ret = heap.brk(brk);
        assert_eq!(ret, brk);

        let steps = [
            (Page::size(), 1),
            (Page::size() / 2, 1),
            (Page::size() + Page::size() / 2, 2),
            (pages * Page::size(), pages),
        ];

        for (s, allocated) in steps.iter() {
            let addr = heap.mmap(0, *s, PROT, FLAGS, -1, 0).unwrap();

            for page in brk_page..heap.pages.len() - allocated {
                assert!(!heap.is_allocated(page));
            }
            for page in heap.pages.len() - allocated..heap.pages.len() {
                assert!(heap.is_allocated(page));
            }

            heap.munmap::<c_void>(addr, *s).unwrap();
        }

        // try to allocate memory whose size exceeds the total heap size
        let len = heap.pages.len() * Page::size() + 1;
        let ret = heap.mmap::<c_void>(0, len, PROT, FLAGS, -1, 0);
        assert_eq!(ret.unwrap_err(), libc::ENOMEM);
    }

    #[test]
    fn mmap_munmap_oneshot() {
        let bytes = &mut [0; Page::size() * NUM_PAGES];
        let mut heap = new_checked(bytes);

        let pages = heap.pages.len();
        oneshot(&mut heap, pages);
        oneshot(&mut heap, pages / 2);
    }

    fn incremental(heap: &mut Heap, pages: usize) {
        let brk_page = heap.pages.len() - pages;
        let brk = heap.metadata.brk.start + brk_page * Page::size();
        let ret = heap.brk(brk);
        assert_eq!(ret, brk);

        let steps = [Page::size(), Page::size() / 2];

        for s in steps.iter() {
            let mut addrs = [null_mut::<libc::c_void>(); NUM_PAGES];

            for i in brk_page..heap.pages.len() {
                let addr = heap.mmap(0, *s, PROT, FLAGS, -1, 0).unwrap();
                addrs[i] = addr;
            }

            for page in brk_page..heap.pages.len() {
                assert!(heap.is_allocated(page));
            }

            // try to allocate memory but no free pages
            let ret = heap.mmap::<c_void>(0, *s, PROT, FLAGS, -1, 0);
            assert_eq!(ret.unwrap_err(), libc::ENOMEM);

            for i in brk_page..heap.pages.len() {
                heap.munmap(addrs[i], *s).unwrap();
            }

            for page in brk_page..heap.pages.len() {
                assert!(!heap.is_allocated(page));
            }
        }
    }

    #[test]
    fn mmap_munmap_incremental() {
        let bytes = &mut [0; Page::size() * NUM_PAGES];
        let mut heap = new_checked(bytes);

        let pages = heap.pages.len();
        incremental(&mut heap, pages);
        incremental(&mut heap, pages / 2);
    }
}
