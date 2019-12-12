// Copyright 2020 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! syscall serialize/deserialize
//!
//! Currently it uses a hard coded page and an I/O trigger.
//! We might want to switch to MMIO.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![no_std]

use serde::{Deserialize, Serialize};

/// The syscalls to be serialized/deserialized via serde
/// for the Hypervisor <-> VM syscall proxy
#[derive(Serialize, Deserialize, Debug)]
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

/// The return value of the syscalls to be serialized/deserialized via serde
/// for the Hypervisor <-> VM syscall proxy
#[derive(Serialize, Deserialize, Debug)]
pub enum VmSyscallRet {
    /// int madvise(void *addr, size_t length, int advice);
    Madvise(Result<i32, Error>),
    /// void *mmap(void *addr, size_t length, int prot, int flags, …);
    Mmap(Result<usize, Error>),
    /// void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
    Mremap(Result<usize, Error>),
    /// int munmap(void *addr, size_t length);
    Munmap(Result<i32, Error>),
    /// int mprotect(void *addr, size_t len, int prot);
    Mprotect(Result<i32, Error>),
}

/// The error codes of the syscalls to be serialized/deserialized via serde
/// for the Hypervisor <-> VM syscall proxy
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Error {
    /// standard error
    Errno(i64),
    /// serialize error
    SerializeError,
    /// deserialize error
    DeSerializeError,
}
