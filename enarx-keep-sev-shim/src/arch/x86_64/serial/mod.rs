// SPDX-License-Identifier: Apache-2.0

#[cfg(not(feature = "qemu"))]
#[macro_use]
pub mod syscall_serial;

#[cfg(not(feature = "qemu"))]
pub use syscall_serial::*;

#[cfg(feature = "qemu")]
#[macro_use]
pub mod serial;

#[cfg(feature = "qemu")]
pub use serial::*;
