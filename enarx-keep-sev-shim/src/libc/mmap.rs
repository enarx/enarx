// SPDX-License-Identifier: Apache-2.0

use super::{c_void, vm_syscall};
use vmsyscall::{ErrNo, VmSyscall, VmSyscallRet};

pub fn madvise(addr: *mut c_void, length: usize, advice: i32) -> Result<i32, ErrNo> {
    let s = VmSyscall::Madvise {
        addr: addr as usize,
        length,
        advice,
    };
    let ret = vm_syscall(s)?;
    match ret {
        VmSyscallRet::Madvise(res) => res,
        _ => panic!("Unknown KvmSyscallRet"),
    }
}

pub fn mmap(addr: *mut c_void, length: usize, prot: i32, flags: i32) -> Result<*mut c_void, ErrNo> {
    let s = VmSyscall::Mmap {
        addr: addr as usize,
        length,
        prot,
        flags,
    };
    let ret = vm_syscall(s)?;
    match ret {
        VmSyscallRet::Mmap(res) => match res {
            Ok(l) => Ok(l as _),
            Err(e) => Err(e),
        },
        _ => panic!("Unknown KvmSyscallRet"),
    }
}

pub fn mremap(
    old_address: *mut c_void,
    old_size: usize,
    new_size: usize,
    flags: i32,
) -> Result<*mut c_void, ErrNo> {
    let s = VmSyscall::Mremap {
        old_address: old_address as usize,
        old_size,
        new_size,
        flags,
    };
    let ret = vm_syscall(s)?;
    match ret {
        VmSyscallRet::Mremap(res) => match res {
            Ok(l) => Ok(l as _),
            Err(e) => Err(e),
        },
        _ => panic!("Unknown KvmSyscallRet"),
    }
}

pub fn munmap(addr: *mut c_void, length: usize) -> Result<i32, ErrNo> {
    let s = VmSyscall::Munmap {
        addr: addr as usize,
        length,
    };
    let ret = vm_syscall(s)?;
    match ret {
        VmSyscallRet::Munmap(res) => res,
        _ => panic!("Unknown KvmSyscallRet"),
    }
}

pub fn mprotect(addr: *mut c_void, length: usize, prot: i32) -> Result<i32, ErrNo> {
    let s = VmSyscall::Mprotect {
        addr: addr as usize,
        length,
        prot,
    };
    let ret = vm_syscall(s)?;
    match ret {
        VmSyscallRet::Mprotect(res) => res,
        _ => panic!("Unknown KvmSyscallRet"),
    }
}

pub const MREMAP_MAYMOVE: i32 = 1;
pub const MREMAP_FIXED: i32 = 2;

pub const MADV_NORMAL: i32 = 0;
pub const MADV_RANDOM: i32 = 1;
pub const MADV_SEQUENTIAL: i32 = 2;
pub const MADV_WILLNEED: i32 = 3;
pub const MADV_DONTNEED: i32 = 4;
pub const MADV_FREE: i32 = 8;
pub const MADV_REMOVE: i32 = 9;
pub const MADV_DONTFORK: i32 = 10;
pub const MADV_DOFORK: i32 = 11;
pub const MADV_MERGEABLE: i32 = 12;
pub const MADV_UNMERGEABLE: i32 = 13;
pub const MADV_HUGEPAGE: i32 = 14;
pub const MADV_NOHUGEPAGE: i32 = 15;
pub const MADV_DONTDUMP: i32 = 16;
pub const MADV_DODUMP: i32 = 17;
pub const MADV_HWPOISON: i32 = 100;
pub const PROT_NONE: i32 = 0;
pub const PROT_READ: i32 = 1;
pub const PROT_WRITE: i32 = 2;
pub const PROT_EXEC: i32 = 4;
pub const ENOMEM: i32 = 12;
pub const MAP_HUGETLB: i32 = 0x0004_0000;
pub const MAP_LOCKED: i32 = 0x0001_0000;
pub const MAP_NORESERVE: i32 = 0x04000;
pub const MAP_32BIT: i32 = 0x0040;
pub const MAP_ANON: i32 = 0x0020;
pub const MAP_ANONYMOUS: i32 = 0x0020;
pub const MAP_DENYWRITE: i32 = 0x0800;
pub const MAP_EXECUTABLE: i32 = 0x01000;
pub const MAP_POPULATE: i32 = 0x08000;
pub const MAP_NONBLOCK: i32 = 0x0001_0000;
pub const MAP_STACK: i32 = 0x0002_0000;

pub const MAP_FILE: i32 = 0x0000;
pub const MAP_SHARED: i32 = 0x0001;
pub const MAP_PRIVATE: i32 = 0x0002;
pub const MAP_FIXED: i32 = 0x0010;

pub const MAP_FAILED: *mut c_void = !0 as *mut c_void;
