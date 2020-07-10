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
    pub unsafe fn new(heap: Span<u64>) -> Self {
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

        if base <= addr && addr < ceil {
            return Some(addr - base);
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

    pub fn mmap(
        &mut self,
        addr: usize,
        length: usize,
        prot: usize,
        flags: usize,
        fd: isize,
        offset: usize,
    ) -> usize {
        const RWX: i32 = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        const PA: i32 = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

        let prot = prot as u64 & !(RWX as u64);
        if addr != 0 || fd != -1 || offset != 0 || prot != 0 || flags as u64 != PA as u64 {
            return -libc::EINVAL as _;
        }

        // The number of pages we need for the given length.
        let pages = (length + Page::size() - 1) / Page::size();

        // Find the brk page offset.
        let brk = self.offset_page_up(self.metadata.brk.end).unwrap();

        let end = match self.pages.len().checked_sub(pages) {
            Some(end) => end,
            None => return -libc::ENOMEM as _,
        };

        // Search for pages from the end to the front.
        for i in (brk..=end).rev() {
            let range = i..i + pages;

            if !self.is_allocated_range(range.clone()) {
                for page in range.clone() {
                    self.allocate(page);
                }

                return self.pages[range].as_ptr() as _;
            }
        }

        -libc::ENOMEM as _
    }

    pub fn munmap(&mut self, addr: usize, length: usize) -> usize {
        if addr % Page::size() != 0 {
            return -libc::EINVAL as _;
        }

        let brk = self.offset_page_up(self.metadata.brk.end).unwrap();

        let bot = match self.offset_page_down(addr) {
            Some(page) => page,
            None => return -libc::EINVAL as _,
        };

        let top = match self.offset_page_up(addr + length) {
            Some(page) => page,
            None => return -libc::EINVAL as _,
        };

        if bot < brk {
            return -libc::EINVAL as _;
        }

        for page in bot..top {
            self.deallocate(page);
        }

        0
    }
}
