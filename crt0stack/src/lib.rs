// SPDX-License-Identifier: Apache-2.0

//! Create the initial stack frame to start an ELF binary on Linux
//!
//! # Examples
//!
//! ```rust
//! use crt0stack::{Builder, Entry};
//!
//! let mut stack = [1u8; 512];
//! let stack = stack.as_mut();
//!
//! let mut builder = Builder::new(stack);
//!
//! builder.push("/init").unwrap();
//! let mut builder = builder.done().unwrap();
//!
//! builder.push("HOME=/root").unwrap();
//! let mut builder = builder.done().unwrap();
//!
//! let auxv = [
//!     Entry::Gid(1000),
//!     Entry::Uid(1000),
//!     Entry::Platform("x86_64"),
//!     Entry::ExecFilename("/init"),
//! ];
//! auxv.iter().for_each(|e| builder.push(e).unwrap());
//!
//! let handle = builder.done().unwrap();
//! ```

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::integer_arithmetic)]

mod builder;
mod entry;
mod reader;

pub use builder::{Builder, Handle};
pub use entry::Entry;
pub use reader::Reader;

const AT_NULL: usize = 0;
const AT_EXECFD: usize = 2;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;
const AT_PAGESZ: usize = 6;
const AT_BASE: usize = 7;
const AT_FLAGS: usize = 8;
const AT_ENTRY: usize = 9;
const AT_NOTELF: usize = 10;
const AT_UID: usize = 11;
const AT_EUID: usize = 12;
const AT_GID: usize = 13;
const AT_EGID: usize = 14;
const AT_CLKTCK: usize = 17;
const AT_PLATFORM: usize = 15;
const AT_HWCAP: usize = 16;
const AT_SECURE: usize = 23;
const AT_BASE_PLATFORM: usize = 24;
const AT_RANDOM: usize = 25;
const AT_HWCAP2: usize = 26;
const AT_EXECFN: usize = 31;
const AT_SYSINFO: usize = 32;
const AT_SYSINFO_EHDR: usize = 33;

/// Indicates too many arguments for `serialize`
///
/// Because this crate is no_std, it operates on a fixed sized byte slice.
/// This error indicates, that the arguments `arg`, `env` or `aux` exceed the
/// given slice size.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutOfSpace;

/// State marker for the auxiliary section
pub enum Aux {}

/// State marker for the environment section
pub enum Env {}

/// State marker for the argument section
pub enum Arg {}

/// An opaque stack type used for a stack pointer
#[repr(C, align(16))]
pub struct Stack;
