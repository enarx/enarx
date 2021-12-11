// SPDX-License-Identifier: Apache-2.0

//! Allocate and deallocate memory on a Heap

use core::num::NonZeroUsize;
use core::ops::Range;

use const_default::ConstDefault;
use primordial::Page;

/// This section MUST be marked as RWX in the linker script
#[link_section = ".enarx.heap"]
static mut BLOCK: Block<32768> = Block::new();

/// The keep heap
pub static HEAP: spinning::RwLock<Heap<'_, 32768>> =
    spinning::RwLock::const_new(spinning::RawRwLock::const_new(), unsafe {
        Heap::new(&mut BLOCK)
    });

/// An allocated block of memory
#[repr(C, align(4096))]
struct Block<const N: usize>([Page; N]);

impl<const N: usize> Block<N> {
    const fn new() -> Self {
        Self([Page::DEFAULT; N])
    }
}

/// A heap
pub struct Heap<'a, const N: usize>
where
    [(); N * 64]: Sized,
{
    blk: &'a mut Block<N>,
    map: [u64; N * 64],
    brk: Option<NonZeroUsize>,
}

impl<'a, const N: usize> Heap<'a, N>
where
    [(); N * 64]: Sized,
{
    /// Create a new heap backed by the passed block
    ///
    /// # Safety
    ///
    /// This function is unsafe because it expects the block to be mapped RWX.
    const unsafe fn new(blk: &'a mut Block<N>) -> Self {
        let brk = None;
        let bitmap = [0; N * 64];
        Self {
            blk,
            map: bitmap,
            brk,
        }
    }

    /// Returns the range of the heap area
    pub fn range(&self) -> Range<*const u8> {
        unsafe { self.blk.0.align_to::<u8>().1.as_ptr_range() }
    }

    #[inline(always)]
    const fn idx_bit(page: usize) -> (usize, usize) {
        (page / 64, page % 64)
    }

    fn is_allocated(&self, page: usize) -> bool {
        let (idx, bit) = Self::idx_bit(page);
        self.map[idx] & (1 << bit) != 0
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
        self.map[idx] |= 1 << bit;
    }

    fn deallocate(&mut self, page: usize) {
        let (idx, bit) = Self::idx_bit(page);
        self.map[idx] &= !(1 << bit);
    }

    fn offset(&self, addr: usize) -> Option<usize> {
        let base = self.blk.0.as_ptr() as usize;
        let ceil = base + self.blk.0.len() * Page::SIZE;

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
            .unwrap_or(self.blk.0[0].as_ptr() as _)
    }

    /// Allocate heap memory to address `brk`
    pub fn brk(&mut self, brk: usize) -> usize {
        let old = self.offset_page_up(self.pos()).unwrap();
        let new = match self.offset_page_up(brk) {
            Some(page) => page,
            None => return self.pos(),
        };

        if old < new {
            for page in old..new {
                if self.is_allocated(page) {
                    return self.pos();
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

        self.brk = NonZeroUsize::new(brk);
        brk
    }

    /// mmap memory from the heap
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
        let pages = (length + Page::SIZE - 1) / Page::SIZE;

        // Find the brk page offset.
        let brk = self.offset_page_up(self.pos()).unwrap();

        let end = match self.blk.0.len().checked_sub(pages) {
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

                return Ok(self.blk.0[range].as_mut_ptr() as *mut T);
            }
        }

        Err(libc::ENOMEM)
    }

    /// munmap memory from the heap
    pub fn munmap<T>(&mut self, addr: *const T, length: usize) -> Result<(), libc::c_int> {
        let addr = addr as usize;

        if addr % Page::SIZE != 0 {
            return Err(libc::EINVAL);
        }

        let brk = self.offset_page_up(self.pos()).unwrap();

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

    #[test]
    fn mmap_munmap_oneshot() {
        let mut block = Block::<128>::new();
        let mut heap = unsafe { Heap::new(&mut block) };

        for pages in [128, 64] {
            let brk_page = heap.blk.0.len() - pages;
            let brk = heap.blk as *const _ as usize + brk_page * Page::SIZE;
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

                for page in brk_page..heap.blk.0.len() - allocated {
                    assert!(!heap.is_allocated(page));
                }
                for page in heap.blk.0.len() - allocated..heap.blk.0.len() {
                    assert!(heap.is_allocated(page));
                }

                heap.munmap::<c_void>(addr, s).unwrap();
            }

            // try to allocate memory whose size exceeds the total heap size
            let len = heap.blk.0.len() * Page::SIZE + 1;
            let ret = heap.mmap::<c_void>(0, len, PROT, FLAGS, -1, 0);
            assert_eq!(ret.unwrap_err(), libc::ENOMEM);
        }
    }

    #[test]
    fn mmap_munmap_incremental() {
        let mut block = Block::<128>::new();
        let mut heap = unsafe { Heap::new(&mut block) };

        for pages in [128, 64] {
            let brk_page = heap.blk.0.len() - pages;
            let brk = heap.blk as *const _ as usize + brk_page * Page::SIZE;
            let ret = heap.brk(brk);
            assert_eq!(ret, brk);

            let steps = [Page::SIZE, Page::SIZE / 2];

            for size in steps {
                let mut addrs = [null_mut::<libc::c_void>(); 128];

                for addr in addrs[brk_page..heap.blk.0.len()].iter_mut() {
                    *addr = heap.mmap(0, size, PROT, FLAGS, -1, 0).unwrap();
                }

                for page in brk_page..heap.blk.0.len() {
                    assert!(heap.is_allocated(page));
                }

                // try to allocate memory but no free pages
                let ret = heap.mmap::<c_void>(0, size, PROT, FLAGS, -1, 0);
                assert_eq!(ret.unwrap_err(), libc::ENOMEM);

                for addr in addrs[brk_page..heap.blk.0.len()].iter() {
                    heap.munmap(*addr, size).unwrap();
                }

                for page in brk_page..heap.blk.0.len() {
                    assert!(!heap.is_allocated(page));
                }
            }
        }
    }
}
