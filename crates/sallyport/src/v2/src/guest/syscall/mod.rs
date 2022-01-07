// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific functionality.

#[cfg(test)]
mod tests;

mod argv;
mod fcntl;
mod fstat;
mod passthrough;
mod read;
mod result;
mod write;

pub use argv::*;
pub use fcntl::Fcntl;
pub use fstat::*;
pub use passthrough::*;
pub use read::*;
pub use result::Result;
pub use write::Write;
