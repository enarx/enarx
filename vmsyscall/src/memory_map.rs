// SPDX-License-Identifier: Apache-2.0

//! The `Map` describes the virtual machine address space.
//!
//! Initially copied from:
//! https://github.com/rust-osdev/bootloader/blob/90f5b8910d146d6d489b70a6341d778253663cfa/src/bootinfo/memory_map.rs

use core::cmp::Ordering;
use core::fmt;
use core::ops::{Deref, DerefMut};

use memory::{Offset, Page};
use span::{Contains, Empty, Line};

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
    pub fn new() -> Self {
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
            last_region.range.end = region.range.end;
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
                region.range.start = r.range.end;
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

            let region_cmp = region.range.start.cmp(&r.range.start);
            match region_cmp {
                Ordering::Equal => {
                    if region.range.end < r.range.end {
                        // Case: (r = `r`, R = `region`)
                        // ----rrrrrrrrrrr----
                        // ----RRRR-----------
                        r.range.start = region.range.end;
                        self.add_region(region);
                    } else {
                        // Case: (r = `r`, R = `region`)
                        // ----rrrrrrrrrrr----
                        // ----RRRRRRRRRRRRRR-
                        *r = region;
                    }
                }
                Ordering::Greater => {
                    if region.range.end < r.range.end {
                        // Case: (r = `r`, R = `region`)
                        // ----rrrrrrrrrrr----
                        // ------RRRR---------
                        let mut behind_r = *r;
                        behind_r.range.start = region.range.end;
                        r.range.end = region.range.start;
                        self.add_region(behind_r);
                        self.add_region(region);
                    } else {
                        // Case: (r = `r`, R = `region`)
                        // ----rrrrrrrrrrr----
                        // -----------RRRR---- or
                        // -------------RRRR--
                        r.range.end = region.range.start;
                        self.add_region(region);
                    }
                }
                _ => {
                    // Case: (r = `r`, R = `region`)
                    // ----rrrrrrrrrrr----
                    // --RRRR-------------
                    r.range.start = region.range.end;
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
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Region {
    /// The range of frames that belong to the region.
    pub range: Line<Offset<usize, Page>>,
    /// The type of the region.
    pub region_type: RegionType,
}

impl Region {
    /// Produce an empty `Region`.
    pub fn empty() -> Self {
        Region {
            range: Line {
                start: Offset::from_items(0),
                end: Offset::from_items(0),
            },
            region_type: RegionType::Empty,
        }
    }

    /// Does this region contain the `other` region?
    pub fn contains(&self, other: &Region) -> bool {
        self.range.contains(&other.range)
    }

    /// Does this region extend the `other` region?
    pub fn extends(&self, other: &Region) -> bool {
        self.range.start >= other.range.start && self.range.end > other.range.end
    }

    /// Is this region fully behind the `other` region with no overlap?
    pub fn behind(&self, other: &Region) -> bool {
        self.range.start >= other.range.end
    }

    /// Is this region fully ahead of the `other` region with no overlap?
    pub fn ahead(&self, other: &Region) -> bool {
        self.range.end < other.range.start
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
            let ordering = self.range.start.cmp(&other.range.start);
            match ordering {
                Ordering::Equal => self.range.end.cmp(&other.range.end),
                _ => ordering,
            }
        }
    }
}

impl core::fmt::Debug for Region {
    fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Region")
            .field(
                "range",
                &format_args!(
                    "({:#x}..{:#x})",
                    self.range.start.bytes(),
                    self.range.end.bytes()
                ),
            )
            .field("region_type", &self.region_type)
            .finish()
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
