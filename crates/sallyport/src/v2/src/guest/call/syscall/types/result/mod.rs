// SPDX-License-Identifier: Apache-2.0

//! Platform-specific syscall reply parsing functionality.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;
