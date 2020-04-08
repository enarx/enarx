// SPDX-License-Identifier: Apache-2.0

//! This crate is the interface between the SEV hypervisor (keep) and
//! microkernel (shim). It enables system call proxying to the host.
//!
//! Currently it uses a hard coded page and an I/O trigger.
//! We might want to switch to MMIO.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![no_std]

/// A Linux ErrNo (see libc crate)
pub type ErrNo = i32;

/// System call requests originating from the microkernel.
#[allow(clippy::large_enum_variant, missing_docs)]
pub enum VmSyscall {
    Madvise {
        addr: usize,
        length: usize,
        advice: i32,
    },
    Mmap {
        addr: usize,
        length: usize,
        prot: i32,
        flags: i32,
    },
    Mremap {
        old_address: usize,
        old_size: usize,
        new_size: usize,
        flags: i32,
    },
    Munmap {
        addr: usize,
        length: usize,
    },
    Mprotect {
        addr: usize,
        length: usize,
        prot: i32,
    },
}

#[allow(clippy::large_enum_variant, missing_docs)]
pub enum VmSyscallRet {
    Madvise(Result<i32, ErrNo>),
    Mmap(Result<usize, ErrNo>),
    Mremap(Result<usize, ErrNo>),
    Munmap(Result<i32, ErrNo>),
    Mprotect(Result<i32, ErrNo>),
}
