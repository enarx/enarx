// SPDX-License-Identifier: Apache-2.0

//! This crate is the interface between the SEV hypervisor (keep) and
//! microkernel (shim). It enables system call proxying to the host
//! and serialization of system calls.
//!
//! Currently it uses a hard coded page and an I/O trigger.
//! We might want to switch to MMIO.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(improper_ctypes)]
#![no_std]

pub mod bootinfo;
pub mod memory_map;

use core::fmt::{Debug, Formatter};

impl Debug for VmSyscall {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            VmSyscall::Read { .. } => f.write_str("read(2)"),
            VmSyscall::Write { .. } => f.write_str("write(2)"),
            VmSyscall::Madvise { .. } => f.write_str("madvise(2)"),
            VmSyscall::Mmap { .. } => f.write_str("mmap(2)"),
            VmSyscall::Mremap { .. } => f.write_str("mremap(2)"),
            VmSyscall::Munmap { .. } => f.write_str("munmap(2)"),
            VmSyscall::Mprotect { .. } => f.write_str("mprotect(2)"),
        }
    }
}

/// maximum length of write(2) buffer
pub const WRITE_BUF_LEN: usize = 4000;

/// The syscalls for the Hypervisor <-> VM syscall proxy
#[allow(clippy::large_enum_variant, missing_docs)]
pub enum VmSyscall {
    Read {
        fd: u32,
        count: usize,
    },
    Write {
        fd: u32,
        count: usize,
        data: [u8; WRITE_BUF_LEN],
    },
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
    // Todo: extend with needed hypervisor proxy syscalls
}

/// A Linux ErrNo (see libc crate)
pub type ErrNo = i32;

/// The return value of the syscalls to be serialized/deserialized via serde
/// for the Hypervisor <-> VM syscall proxy
#[allow(clippy::large_enum_variant, missing_docs)]
pub enum VmSyscallRet {
    Read(Result<(i32, [u8; WRITE_BUF_LEN]), ErrNo>),
    Write(Result<i32, ErrNo>),
    Madvise(Result<i32, ErrNo>),
    Mmap(Result<usize, ErrNo>),
    Mremap(Result<usize, ErrNo>),
    Munmap(Result<i32, ErrNo>),
    Mprotect(Result<i32, ErrNo>),
}
