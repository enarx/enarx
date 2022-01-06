// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific functionality.

#[cfg(test)]
mod tests;

mod argv;
mod close;
mod exit;
mod fcntl;
mod fstat;
mod read;
mod result;
mod sync;
mod write;

pub use argv::*;
pub use close::*;
pub use exit::*;
pub use fcntl::Fcntl;
pub use fstat::*;
pub use read::*;
pub use result::*;
pub use sync::*;
pub use write::Write;
