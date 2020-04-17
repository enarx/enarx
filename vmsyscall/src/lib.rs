// SPDX-License-Identifier: Apache-2.0

//! This crate is the interface between the SEV hypervisor (keep) and
//! microkernel (shim). It enables system call proxying to the host.
//!
//! Currently it uses a hard coded page and an I/O trigger.
//! We might want to switch to MMIO.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![no_std]

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

impl core::fmt::Debug for VmSyscall {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            VmSyscall::Madvise {
                addr,
                length,
                advice,
            } => write!(
                f,
                "madvise(addr={:#x}, length={}, advice={:#x})",
                addr, length, advice
            ),
            VmSyscall::Mmap {
                addr,
                length,
                prot,
                flags,
            } => write!(
                f,
                "mmap(addr={:#x}, length={}, prot={:#x}, flags={:#x})",
                addr, length, prot, flags
            ),
            VmSyscall::Mremap {
                old_address,
                old_size,
                new_size,
                flags,
            } => write!(
                f,
                "mremap(old_address={:#x}, old_size={}, new_size={}, flags={:#x})",
                old_address, old_size, new_size, flags
            ),
            VmSyscall::Munmap { addr, length } => {
                write!(f, "munmap(addr={:#x}, length={})", addr, length)
            }
            VmSyscall::Mprotect { addr, length, prot } => write!(
                f,
                "mprotect(addr={:#x}, length={}, prot={:#x})",
                addr, length, prot
            ),
        }
    }
}

/// Marker trait for non-enum syscall return values.
pub trait ProxiedSyscall {}

/// The result of a proxied syscall. The enclosed trait-constrained type
/// can be used to provide "output" parameters to the microkernel so that
/// it may unpack them and write to its own pages. For example, a read
/// call must write bytes into a buffer. This allows us to copy that
/// buffer to the shared syscall page so the microkernel can unpack
/// it. Furthermore, this type allows more flexibility for expressing what
/// the return value is by implementing core::convert::Into<U> for each
/// concrete instance of a SyscallRet.
#[derive(Copy, Clone)]
pub struct SyscallRet<T: ProxiedSyscall> {
    /// Data region containing "output" parameters that are modified
    /// during the syscall and therefore the microkernel must unpack
    /// these and update the appropriate data items to complete the syscall.
    data: T,
    ret: usize,
}

impl<T: ProxiedSyscall + Copy> SyscallRet<T> {
    /// Construct a new SyscallRet value.
    pub fn new(ret: usize, data: T) -> Self {
        Self { data, ret }
    }

    /// Expose the "output" parameter data. For many syscalls this may
    /// very well be an empty struct and therefore not relevant.
    pub fn data(&self) -> T {
        self.data
    }
}

/// The result of a proxied Madvise syscall.
#[derive(Copy, Clone)]
pub struct MadviseRet;
impl ProxiedSyscall for MadviseRet {}

impl Into<i32> for SyscallRet<MadviseRet> {
    fn into(self) -> i32 {
        self.ret as _
    }
}

/// The result of a proxied Mmap syscall.
#[derive(Copy, Clone)]
pub struct MmapRet;
impl ProxiedSyscall for MmapRet {}

impl Into<memory::Address<usize, ()>> for SyscallRet<MmapRet> {
    fn into(self) -> memory::Address<usize, ()> {
        unsafe { memory::Address::unchecked(self.ret) }
    }
}

/// The result of a proxied Mremap syscall.
#[derive(Copy, Clone)]
pub struct MremapRet;
impl ProxiedSyscall for MremapRet {}

impl Into<memory::Address<usize, ()>> for SyscallRet<MremapRet> {
    fn into(self) -> memory::Address<usize, ()> {
        unsafe { memory::Address::unchecked(self.ret) }
    }
}

/// The result of a proxied Munmap syscall.
#[derive(Copy, Clone)]
pub struct MunmapRet;
impl ProxiedSyscall for MunmapRet {}

impl Into<i32> for SyscallRet<MunmapRet> {
    fn into(self) -> i32 {
        self.ret as _
    }
}

/// The result of a proxied Mprotect syscall.
#[derive(Copy, Clone)]
pub struct MprotectRet;
impl ProxiedSyscall for MprotectRet {}

impl Into<i32> for SyscallRet<MprotectRet> {
    fn into(self) -> i32 {
        self.ret as _
    }
}
