// SPDX-License-Identifier: Apache-2.0

//! Duplicated from the x86_64 crate, because we want USER_ACCESSIBLE in newly allocated page tables
//!
//! can be removed, if we can get patches upstream
//! see https://github.com/rust-osdev/x86_64/pull/114

pub mod paging;
pub use paging::OffsetPageTable;
