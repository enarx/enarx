// SPDX-License-Identifier: Apache-2.0

//! The `Map` describes the virtual machine address space.
//!
//! Initially copied from:
//! https://github.com/rust-osdev/bootloader/blob/90f5b8910d146d6d489b70a6341d778253663cfa/src/bootinfo/memory_map.rs

use core::cmp::Ordering;
use core::fmt;
use core::ops::{Deref, DerefMut};

pub(crate) const PAGE_SIZE: u64 = 4096;

const MAX_MEMORY_MAP_SIZE: usize = 64;

/// A map of the physical memory regions of the underlying machine.
#[derive(Clone)]
#[repr(C)]
pub struct Map {
    entries: [Region; MAX_MEMORY_MAP_SIZE],
    // u64 instead of usize so that the structure layout is platform
    // independent
    next_entry_index: u64,
}

impl Map {
    /// Produce an empty `Map`.
    pub const fn new() -> Self {
        Map {
            entries: [Region::empty(); MAX_MEMORY_MAP_SIZE],
            next_entry_index: 0,
        }
    }

    /// Mark a region as usable.
    pub fn set_region_type_usable(&mut self, region_type: RegionType) {
        self.iter_mut()
            .filter(|r| r.region_type == region_type)
            .for_each(|r| r.region_type = RegionType::Usable);
    }

    /// Add a region to the `Map`.
    pub fn add_region(&mut self, region: Region) {
        if let Some(last_region) = self
            .entries
            .iter_mut()
            .filter(|r| r.region_type == region.region_type)
            .find(|r| r.contains(&region))
        {
            last_region.range.end_frame_number = region.range.end_frame_number;
        }

        assert!(
            self.next_entry_index() < MAX_MEMORY_MAP_SIZE,
            "too many memory regions in memory map"
        );

        self.entries[self.next_entry_index()] = region;
        self.next_entry_index += 1;
        self.sort();
    }

    /// Mark a region as allocated.
    pub fn mark_allocated_region(&mut self, region: Region) {
        let mut region = region;
        for r in self.iter_mut() {
            // New region inside region of same type
            if r.region_type == region.region_type && r.contains(&region) {
                return;
            }

            // New region extends old region
            if r.region_type == region.region_type && region.extends(&r) {
                region.range.start_frame_number = r.range.end_frame_number;
            }

            if region.behind(r) {
                continue;
            }
            if region.ahead(r) {
                continue;
            }

            if r.region_type != RegionType::Usable {
                panic!(
                    "region {:x?} overlaps with non-usable region {:x?}",
                    region, r
                );
            }

            let region_cmp = region
                .range
                .start_frame_number
                .cmp(&r.range.start_frame_number);
            match region_cmp {
                Ordering::Equal => {
                    if region.range.end_frame_number < r.range.end_frame_number {
                        // Case: (r = `r`, R = `region`)
                        // ----rrrrrrrrrrr----
                        // ----RRRR-----------
                        r.range.start_frame_number = region.range.end_frame_number;
                        self.add_region(region);
                    } else {
                        // Case: (r = `r`, R = `region`)
                        // ----rrrrrrrrrrr----
                        // ----RRRRRRRRRRRRRR-
                        *r = region;
                    }
                }
                Ordering::Greater => {
                    if region.range.end_frame_number < r.range.end_frame_number {
                        // Case: (r = `r`, R = `region`)
                        // ----rrrrrrrrrrr----
                        // ------RRRR---------
                        let mut behind_r = *r;
                        behind_r.range.start_frame_number = region.range.end_frame_number;
                        r.range.end_frame_number = region.range.start_frame_number;
                        self.add_region(behind_r);
                        self.add_region(region);
                    } else {
                        // Case: (r = `r`, R = `region`)
                        // ----rrrrrrrrrrr----
                        // -----------RRRR---- or
                        // -------------RRRR--
                        r.range.end_frame_number = region.range.start_frame_number;
                        self.add_region(region);
                    }
                }
                _ => {
                    // Case: (r = `r`, R = `region`)
                    // ----rrrrrrrrrrr----
                    // --RRRR-------------
                    r.range.start_frame_number = region.range.end_frame_number;
                    self.add_region(region);
                }
            }

            return;
        }
        panic!(
            "region {:x?} is not a usable memory region\n{:#?}",
            region, self
        );
    }

    /// Sort the `Map` by region index.
    pub fn sort(&mut self) {
        self.entries.sort_unstable();
        if let Some(first_zero_index) = self.entries.iter().position(|r| r.range.is_empty()) {
            self.next_entry_index = first_zero_index as u64;
        }
    }

    /// Peek the next index value.
    fn next_entry_index(&self) -> usize {
        self.next_entry_index as usize
    }
}

impl Default for Map {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Map {
    type Target = [Region];

    fn deref(&self) -> &Self::Target {
        &self.entries[0..self.next_entry_index()]
    }
}

impl DerefMut for Map {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let next_index = self.next_entry_index();
        &mut self.entries[0..next_index]
    }
}

impl fmt::Debug for Map {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Represents a region of physical memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Region {
    /// The range of frames that belong to the region.
    pub range: FrameRange,
    /// The type of the region.
    pub region_type: RegionType,
}

impl Region {
    /// Produce an empty `Region`.
    pub const fn empty() -> Self {
        Region {
            range: FrameRange {
                start_frame_number: 0,
                end_frame_number: 0,
            },
            region_type: RegionType::Empty,
        }
    }

    /// Does this region contain the `other` region?
    pub fn contains(&self, other: &Region) -> bool {
        self.range.start_frame_number <= other.range.start_frame_number
            && self.range.end_frame_number >= other.range.end_frame_number
    }

    /// Does this region extend the `other` region?
    pub fn extends(&self, other: &Region) -> bool {
        self.range.start_frame_number >= other.range.start_frame_number
            && self.range.end_frame_number > other.range.end_frame_number
    }

    /// Is this region fully behind the `other` region with no overlap?
    pub fn behind(&self, other: &Region) -> bool {
        self.range.start_frame_number >= other.range.end_frame_number
    }

    /// Is this region fully ahead of the `other` region with no overlap?
    pub fn ahead(&self, other: &Region) -> bool {
        self.range.end_frame_number < other.range.start_frame_number
    }
}

impl PartialOrd for Region {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Region {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.range.is_empty() {
            Ordering::Greater
        } else if other.range.is_empty() {
            Ordering::Less
        } else {
            let ordering = self
                .range
                .start_frame_number
                .cmp(&other.range.start_frame_number);
            match ordering {
                Ordering::Equal => self
                    .range
                    .end_frame_number
                    .cmp(&other.range.end_frame_number),
                _ => ordering,
            }
        }
    }
}

/// A range of frames with an exclusive upper bound.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FrameRange {
    /// The frame _number_ of the first 4KiB frame in the region.
    ///
    /// This convert this frame number to a physical address, multiply it with the
    /// page size (4KiB).
    pub start_frame_number: u64,
    /// The frame _number_ of the first 4KiB frame that does no longer belong to the region.
    ///
    /// This convert this frame number to a physical address, multiply it with the
    /// page size (4KiB).
    pub end_frame_number: u64,
}

impl FrameRange {
    /// Create a new FrameRange from the passed start_addr and end_addr.
    ///
    /// The end_addr is exclusive.
    pub fn new(start_addr: u64, end_addr: u64) -> Self {
        let last_byte = end_addr - 1;
        FrameRange {
            start_frame_number: start_addr / PAGE_SIZE,
            end_frame_number: (last_byte / PAGE_SIZE) + 1,
        }
    }

    /// Returns true if the frame range contains no frames.
    pub fn is_empty(&self) -> bool {
        self.start_frame_number == self.end_frame_number
    }

    /// Length of the frame range
    pub fn len(&self) -> u64 {
        self.end_frame_number - self.start_frame_number
    }

    /// Returns the physical start address of the memory region.
    pub fn start_addr(&self) -> u64 {
        self.start_frame_number * PAGE_SIZE
    }

    /// Returns the physical end address of the memory region.
    pub fn end_addr(&self) -> u64 {
        self.end_frame_number * PAGE_SIZE
    }
}

impl fmt::Debug for FrameRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "FrameRange({:#x}..{:#x})",
            self.start_addr(),
            self.end_addr()
        )
    }
}

/// Represents possible types for memory regions.
#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum RegionType {
    Usable,
    InUse,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    BadMemory,
    Kernel,
    App,
    Bootloader,
    FrameZero,
    Empty,
}
