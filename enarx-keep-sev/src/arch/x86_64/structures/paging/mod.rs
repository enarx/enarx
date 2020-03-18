// SPDX-License-Identifier: Apache-2.0

//! Abstractions for page tables and other paging related structures.
//!
//! Page tables translate virtual memory “pages” to physical memory “frames”.

pub use self::frame::PhysFrame;
pub use self::page::{Page, PageSize, Size1GiB, Size2MiB, Size4KiB};
pub use self::page_table::{PageTable, PageTableFlags};

pub mod frame;
pub mod page;
pub mod page_table;
