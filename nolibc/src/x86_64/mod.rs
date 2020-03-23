// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unreadable_literal)]

pub mod error;
pub mod syscall;

pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
pub const PROT_NONE: u64 = 0;

pub const MAP_SHARED: u64 = 1;
pub const MAP_PRIVATE: u64 = 2;
pub const MAP_SHARED_VALIDATE: u64 = 3;
pub const MAP_TYPE: u64 = 15;
pub const MAP_FIXED: u64 = 16;
pub const MAP_FILE: u64 = 0;
pub const MAP_ANONYMOUS: u64 = 32;
pub const MAP_ANON: u64 = 32;
pub const MAP_HUGE_SHIFT: u64 = 26;
pub const MAP_HUGE_MASK: u64 = 63;
pub const MAP_32BIT: u64 = 64;
pub const MAP_GROWSDOWN: u64 = 256;
pub const MAP_DENYWRITE: u64 = 2048;
pub const MAP_EXECUTABLE: u64 = 4096;
pub const MAP_LOCKED: u64 = 8192;
pub const MAP_NORESERVE: u64 = 16384;
pub const MAP_POPULATE: u64 = 32768;
pub const MAP_NONBLOCK: u64 = 65536;
pub const MAP_STACK: u64 = 131072;
pub const MAP_HUGETLB: u64 = 262144;
pub const MAP_SYNC: u64 = 524288;
pub const MAP_FIXED_NOREPLACE: u64 = 1048576;
