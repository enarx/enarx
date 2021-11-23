// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific functionality.

#[cfg(test)]
mod tests;

mod argv;
mod close;
mod exit;
mod fstat;
mod read;
mod result;
mod write;

pub use argv::*;
pub use close::*;
pub use exit::*;
pub use fstat::*;
pub use read::*;
pub use result::*;
pub use write::*;
