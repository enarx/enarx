// SPDX-License-Identifier: Apache-2.0

//! Shared components for the shim and the loader
//! # Loader
//!
//! The loader calls [`BootInfo::calculate`] to get the offset for the shim and the code.
//!
//! The loader starts the virtual machine and jumps to the shim entry point.
//!
//! The shim expects the following registers:
//! * `%rdi` = `SYSCALL_PHYS_ADDR`, address of the page, where the loader placed a copy of `BootInfo`
//!            and which is used later on for the communication with the shim.
//! * `%rsi` = the start address of the shim memory (contents of `BootInfo.shim.start`)
//! * `%rip` = the address of the shim entry point taken from the elf header
//!
//! Although `%rsi` is redundant, it makes the initial startup function of the `shim` much easier.
//!
//! # Shim
//!
//! The shim sets the unencrypted flag for the page at `SYSCALL_PHYS_ADDR` and uses that page
//! for further communication with the host.
//!
//! The `setup` area must not be touched, unless the shim sets up the page tables,
//! the GDT and the IDT. After that the setup area is used as free memory except for the pages
//! to communicate with the host.
//!
//! To proxy a syscall to the host, the shim triggers a `#VMEXIT` via I/O on the
//! [`SYSCALL_TRIGGER_PORT`].
//!
//! [`BootInfo::calculate`]: struct.BootInfo.html#method.calculate
//! [`SYSCALL_TRIGGER_PORT`]: constant.SYSCALL_TRIGGER_PORT.html

#![no_std]
#![deny(clippy::all)]
#![deny(clippy::integer_arithmetic)]
#![deny(missing_docs)]

/// I/O port used to trigger a `#VMEXIT`
///
/// FIXME: might change to another mechanism in the future
pub const SYSCALL_TRIGGER_PORT: u16 = 0xFF;

use bounds::{Line, Span};
use units::bytes;

// page align - to ease debugging, set to 1MiB in debug builds
#[cfg(debug_assertions)]
#[allow(clippy::integer_arithmetic)]
const ALIGN_SECTION: usize = bytes!(1; MiB);

#[cfg(not(debug_assertions))]
#[allow(clippy::integer_arithmetic)]
const ALIGN_SECTION: usize = bytes!(4; KiB);

#[inline(always)]
#[allow(clippy::integer_arithmetic)]
const fn lower(value: usize, boundary: usize) -> usize {
    value / boundary * boundary
}

#[inline(always)]
fn raise(value: usize, boundary: usize) -> Option<usize> {
    value
        .checked_add(boundary)
        .map(|v| v.wrapping_sub(1))
        .map(|v| lower(v, boundary))
}

#[inline(always)]
fn above(rel: impl Into<Line<usize>>, size: usize) -> Option<Span<usize>> {
    raise(rel.into().end, ALIGN_SECTION).map(|val| Span {
        start: val,
        count: size,
    })
}

/// Basic information for the shim and the loader
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct BootInfo {
    /// Memory for the loader to place page tables, GDT and IDT and the
    /// shared pages
    pub setup: Line<usize>,
    /// Memory where the `code` is / has to be loaded
    pub code: Line<usize>,
    /// Memory where the `shim` is / has to be loaded
    pub shim: Line<usize>,
    /// Memory size
    pub mem_size: usize,
    /// Loader virtual memory offset to shim physical memory
    pub virt_offset: usize,
}

/// Error returned, if the virtual machine memory is to small for the shim to operate.
///
/// Because of `no_std` it does not implement `std::error::Error`.
pub struct NoMemory(());

impl BootInfo {
    /// Calculates the memory layout of various components
    ///
    /// Given the size of the available memory `mem_size`, the addresses of `setup`
    /// and the size of `shim` and `code`, this function calculates
    /// the layout for the `shim` and `code`.
    ///
    /// # Errors
    ///
    /// `NoMemory`: if there is not enough memory for the shim to operate
    #[inline]
    pub fn calculate(
        mem_size: usize,
        virt_offset: usize,
        setup: Line<usize>,
        shim: Span<usize>,
        code: Span<usize>,
    ) -> Result<Self, NoMemory> {
        let shim: Line<usize> = above(setup, shim.count).ok_or(NoMemory(()))?.into();
        let code: Line<usize> = above(shim, code.count).ok_or(NoMemory(()))?.into();

        // FIXME: add more space for needed stack + heap + other stuff
        if code.end >= mem_size {
            // shim + code does not fit in VM memory
            return Err(NoMemory(()));
        }

        Ok(Self {
            setup,
            code,
            shim,
            mem_size,
            virt_offset,
        })
    }
}
