// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific functionality.

#[cfg(test)]
mod tests;

mod argv;
mod bind;
mod connect;
mod fcntl;
mod fstat;
mod passthrough;
mod read;
mod result;
mod setsockopt;
mod stub;
mod write;

pub use argv::*;
pub use bind::*;
pub use connect::*;
pub use fcntl::Fcntl;
pub use fstat::*;
pub use passthrough::*;
pub use read::*;
pub use result::Result;
pub use setsockopt::*;
pub use stub::*;
pub use write::Write;
