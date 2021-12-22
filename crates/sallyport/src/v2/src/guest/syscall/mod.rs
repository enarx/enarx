// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific functionality.

#[cfg(test)]
mod tests;

mod argv;
mod exit;
mod result;

pub use argv::*;
pub use exit::*;
pub use result::*;
