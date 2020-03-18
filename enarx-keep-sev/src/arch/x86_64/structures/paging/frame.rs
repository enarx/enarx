// SPDX-License-Identifier: Apache-2.0

//! Abstractions for default-sized and huge physical memory frames.

use super::super::super::PhysAddr;
use super::page::{PageSize, Size4KiB};
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Sub, SubAssign};

/// A physical memory frame.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct PhysFrame<S: PageSize = Size4KiB> {
    start_address: PhysAddr,
    size: PhantomData<S>,
}

impl<S: PageSize> PhysFrame<S> {
    /// Returns the frame that starts at the given virtual address.
    ///
    /// Returns an error if the address is not correctly aligned (i.e. is not a valid frame start).
    pub fn from_start_address(address: PhysAddr) -> Result<Self, ()> {
        if !address.is_aligned(S::SIZE) {
            return Err(());
        }
        Ok(PhysFrame::containing_address(address))
    }

    /// Returns the frame that contains the given physical address.
    pub fn containing_address(address: PhysAddr) -> Self {
        PhysFrame {
            start_address: address.align_down(S::SIZE),
            size: PhantomData,
        }
    }

    /// Returns the start address of the frame.
    pub fn start_address(self) -> PhysAddr {
        self.start_address
    }

    /// Returns a range of frames, exclusive `end`.
    pub fn range(start: PhysFrame<S>, end: PhysFrame<S>) -> PhysFrameRange<S> {
        PhysFrameRange { start, end }
    }
}

impl<S: PageSize> fmt::Debug for PhysFrame<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "PhysFrame[{}]({:#x})",
            S::SIZE_AS_DEBUG_STR,
            self.start_address().as_u64()
        ))
    }
}

impl<S: PageSize> Add<u64> for PhysFrame<S> {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        PhysFrame::containing_address(self.start_address() + rhs * S::SIZE)
    }
}

impl<S: PageSize> AddAssign<u64> for PhysFrame<S> {
    fn add_assign(&mut self, rhs: u64) {
        *self = *self + rhs;
    }
}

impl<S: PageSize> Sub<u64> for PhysFrame<S> {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        PhysFrame::containing_address(self.start_address() - rhs * S::SIZE)
    }
}

impl<S: PageSize> SubAssign<u64> for PhysFrame<S> {
    fn sub_assign(&mut self, rhs: u64) {
        *self = *self - rhs;
    }
}

impl<S: PageSize> Sub<PhysFrame<S>> for PhysFrame<S> {
    type Output = u64;
    fn sub(self, rhs: PhysFrame<S>) -> Self::Output {
        (self.start_address - rhs.start_address) / S::SIZE
    }
}

/// An range of physical memory frames, exclusive the upper bound.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PhysFrameRange<S: PageSize = Size4KiB> {
    /// The start of the range, inclusive.
    pub start: PhysFrame<S>,
    /// The end of the range, exclusive.
    pub end: PhysFrame<S>,
}

impl<S: PageSize> Iterator for PhysFrameRange<S> {
    type Item = PhysFrame<S>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            let frame = self.start;
            self.start += 1;
            Some(frame)
        } else {
            None
        }
    }
}

impl<S: PageSize> fmt::Debug for PhysFrameRange<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PhysFrameRange")
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

/// An range of physical memory frames, inclusive the upper bound.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PhysFrameRangeInclusive<S: PageSize = Size4KiB> {
    /// The start of the range, inclusive.
    pub start: PhysFrame<S>,
    /// The start of the range, exclusive.
    pub end: PhysFrame<S>,
}

impl<S: PageSize> Iterator for PhysFrameRangeInclusive<S> {
    type Item = PhysFrame<S>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start <= self.end {
            let frame = self.start;
            self.start += 1;
            Some(frame)
        } else {
            None
        }
    }
}
