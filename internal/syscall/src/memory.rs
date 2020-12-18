// SPDX-License-Identifier: Apache-2.0

//! memory syscalls

use sallyport::Result;
use untrusted::UntrustedRef;

/// memory syscalls
pub trait MemorySyscallHandler {
    /// syscall
    fn brk(&mut self, addr: *const u8) -> Result;

    /// syscall
    fn mmap(
        &mut self,
        addr: UntrustedRef<u8>,
        length: libc::size_t,
        prot: libc::c_int,
        flags: libc::c_int,
        fd: libc::c_int,
        offset: libc::off_t,
    ) -> Result;

    /// syscall
    fn munmap(&mut self, addr: UntrustedRef<u8>, length: libc::size_t) -> Result;

    /// syscall
    fn madvise(
        &mut self,
        addr: *const libc::c_void,
        length: libc::size_t,
        advice: libc::c_int,
    ) -> Result;

    /// syscall
    fn mprotect(&mut self, addr: UntrustedRef<u8>, len: libc::size_t, prot: libc::c_int) -> Result;
}
