// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific functionality.

#[cfg(test)]
mod tests;

mod argv;
mod exit;
mod read;
mod result;
mod write;

pub use argv::*;
pub use exit::*;
pub use read::*;
pub use result::*;
pub use write::*;
