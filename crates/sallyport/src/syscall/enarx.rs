// SPDX-License-Identifier: Apache-2.0

//! enarx syscalls

use crate::untrusted::{UntrustedRef, UntrustedRefMut};
use crate::Result;
use primordial::Address;

/// enarx syscalls
pub trait EnarxSyscallHandler {
    /// Enarx syscall - get attestation
    fn get_attestation(
        &mut self,
        nonce: UntrustedRef<u8>,
        nonce_len: libc::size_t,
        buf: UntrustedRefMut<u8>,
        buf_len: libc::size_t,
    ) -> Result;
}

/// Basic information about the host memory, the shim requests
/// from the loader via the [`SYS_ENARX_MEM_INFO`](super::SYS_ENARX_MEM_INFO) syscall
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct MemInfo {
    /// Loader virtual address of initial shim physical memory.
    ///
    /// Obsolete, if [host side syscall verification and address translation](https://github.com/enarx/enarx/issues/957)
    /// is implemented.
    pub virt_start: Address<usize, u8>,
    /// Number of memory slot available for ballooning
    ///
    /// KVM only has a limited number of memory ballooning slots, which varies by technology and kernel version.
    /// Knowing this number helps the shim allocator to decide how much memory to allocate for each slot.
    pub mem_slots: usize,
}
