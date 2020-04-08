// SPDX-License-Identifier: Apache-2.0

//! Currently it uses a hard coded page and an I/O trigger.
//! We might want to switch to MMIO.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![no_std]

/// A Linux ErrNo (see libc crate)
pub type ErrNo = i32;

pub enum VmSyscall {
    /// int madvise(void *addr, size_t length, int advice);
    Madvise {
        /// see madvise(2)
        addr: usize,
        /// see madvise(2)
        length: usize,
        /// see madvise(2)
        advice: i32,
    },
    /// void *mmap(void *addr, size_t length, int prot, int flags, …);
    Mmap {
        /// see mmap(2)
        addr: usize,
        /// see mmap(2)
        length: usize,
        /// see mmap(2)
        prot: i32,
        /// see mmap(2)
        flags: i32,
    },
    /// void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
    Mremap {
        /// see mremap(2)
        old_address: usize,
        /// see mremap(2)
        old_size: usize,
        /// see mremap(2)
        new_size: usize,
        /// see mremap(2)
        flags: i32,
    },
    /// int munmap(void *addr, size_t length);
    Munmap {
        /// see munmap(2)
        addr: usize,
        /// see munmap(2)
        length: usize,
    },
    /// int mprotect(void *addr, size_t len, int prot);
    Mprotect {
        /// see mprotect(2)
        addr: usize,
        /// see mprotect(2)
        length: usize,
        /// see mprotect(2)
        prot: i32,
    },
    // Todo: extend with needed hypervisor proxy syscalls
}

/// for the Hypervisor <-> VM syscall proxy
#[allow(clippy::large_enum_variant)]
pub enum VmSyscallRet {
    Madvise(Result<i32, ErrNo>),
    Mmap(Result<usize, ErrNo>),
    Mremap(Result<usize, ErrNo>),
    Munmap(Result<i32, ErrNo>),
    Mprotect(Result<i32, ErrNo>),
}
