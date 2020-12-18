// SPDX-License-Identifier: Apache-2.0

//! enarx syscalls

use sallyport::Result;
use untrusted::{UntrustedRef, UntrustedRefMut};

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
