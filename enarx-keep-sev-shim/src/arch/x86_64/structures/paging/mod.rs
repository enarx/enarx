// SPDX-License-Identifier: Apache-2.0

pub(crate) mod mapper;

pub use self::mapper::MappedPageTable;
pub use self::mapper::Mapper;
#[cfg(target_arch = "x86_64")]
#[doc(no_inline)]
pub use self::mapper::OffsetPageTable;

pub use x86_64::structures::paging::{
    FrameAllocator, Page, PageTable, PageTableFlags, PhysFrame, Size1GiB, Size2MiB, Size4KiB,
    UnusedPhysFrame,
};
