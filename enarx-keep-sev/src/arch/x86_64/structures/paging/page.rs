// SPDX-License-Identifier: Apache-2.0

//! Abstractions for default-sized and huge virtual memory pages.

use super::super::super::VirtAddr;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Sub, SubAssign};

/// Trait for abstracting over the three possible page sizes on x86_64, 4KiB, 2MiB, 1GiB.
pub trait PageSize: Copy + Eq + PartialOrd + Ord {
    /// The page size in bytes.
    const SIZE: u64;

    /// A string representation of the page size for debug output.
    const SIZE_AS_DEBUG_STR: &'static str;
}

/// This trait is implemented for 4KiB and 2MiB pages, but not for 1GiB pages.
pub trait NotGiantPageSize: PageSize {}

/// A standard 4KiB page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Size4KiB {}

/// A “huge” 2MiB page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Size2MiB {}

/// A “giant” 1GiB page.
///
/// (Only available on newer x86_64 CPUs.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Size1GiB {}

impl PageSize for Size4KiB {
    const SIZE: u64 = 4096;
    const SIZE_AS_DEBUG_STR: &'static str = "4KiB";
}

impl NotGiantPageSize for Size4KiB {}

impl PageSize for Size2MiB {
    const SIZE: u64 = Size4KiB::SIZE * 512;
    const SIZE_AS_DEBUG_STR: &'static str = "2MiB";
}

impl NotGiantPageSize for Size2MiB {}

impl PageSize for Size1GiB {
    const SIZE: u64 = Size2MiB::SIZE * 512;
    const SIZE_AS_DEBUG_STR: &'static str = "1GiB";
}

/// A virtual memory page.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct Page<S: PageSize = Size4KiB> {
    start_address: VirtAddr,
    size: PhantomData<S>,
}

impl<S: PageSize> Page<S> {
    /// Returns the page that contains the given virtual address.
    pub fn containing_address(address: VirtAddr) -> Self {
        Page {
            start_address: address.align_down(S::SIZE),
            size: PhantomData,
        }
    }

    /// Returns the start address of the page.
    pub fn start_address(self) -> VirtAddr {
        self.start_address
    }
}

impl<S: PageSize> fmt::Debug for Page<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "Page[{}]({:#x})",
            S::SIZE_AS_DEBUG_STR,
            self.start_address().as_u64()
        ))
    }
}

impl<S: PageSize> Add<u64> for Page<S> {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Page::containing_address(self.start_address() + rhs * S::SIZE)
    }
}

impl<S: PageSize> AddAssign<u64> for Page<S> {
    fn add_assign(&mut self, rhs: u64) {
        *self = *self + rhs;
    }
}

impl<S: PageSize> Sub<u64> for Page<S> {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Page::containing_address(self.start_address() - rhs * S::SIZE)
    }
}

impl<S: PageSize> SubAssign<u64> for Page<S> {
    fn sub_assign(&mut self, rhs: u64) {
        *self = *self - rhs;
    }
}

impl<S: PageSize> Sub<Self> for Page<S> {
    type Output = u64;
    fn sub(self, rhs: Self) -> Self::Output {
        (self.start_address - rhs.start_address) / S::SIZE
    }
}

/// A range of pages with exclusive upper bound.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PageRange<S: PageSize = Size4KiB> {
    /// The start of the range, inclusive.
    pub start: Page<S>,
    /// The end of the range, exclusive.
    pub end: Page<S>,
}

impl<S: PageSize> Iterator for PageRange<S> {
    type Item = Page<S>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            let page = self.start;
            self.start += 1;
            Some(page)
        } else {
            None
        }
    }
}

impl<S: PageSize> fmt::Debug for PageRange<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PageRange")
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

/// A range of pages with inclusive upper bound.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PageRangeInclusive<S: PageSize = Size4KiB> {
    /// The start of the range, inclusive.
    pub start: Page<S>,
    /// The end of the range, inclusive.
    pub end: Page<S>,
}

impl<S: PageSize> Iterator for PageRangeInclusive<S> {
    type Item = Page<S>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start <= self.end {
            let page = self.start;
            self.start += 1;
            Some(page)
        } else {
            None
        }
    }
}

impl<S: PageSize> fmt::Debug for PageRangeInclusive<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PageRangeInclusive")
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}
