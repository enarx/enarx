// SPDX-License-Identifier: Apache-2.0

//! enarx syscalls

use crate::syscall::{
    BaseSyscallHandler, SYS_ENARX_GDB_PEEK, SYS_ENARX_GDB_READ, SYS_ENARX_GDB_START,
    SYS_ENARX_GDB_WRITE,
};
use crate::untrusted::{AddressValidator, UntrustedRef, UntrustedRefMut, ValidateSlice};
use crate::Register;
use crate::{request, Block, Result};
use primordial::Address;

/// enarx syscalls
pub trait EnarxSyscallHandler: BaseSyscallHandler + AddressValidator + Sized {
    /// Enarx syscall - get attestation
    fn get_attestation(
        &mut self,
        nonce: UntrustedRef<u8>,
        nonce_len: libc::size_t,
        buf: UntrustedRefMut<u8>,
        buf_len: libc::size_t,
    ) -> Result;

    /// gdb extension
    fn gdb_start(&mut self) -> Result {
        self.trace("gdb_start", 0);
        unsafe { self.proxy(request!(SYS_ENARX_GDB_START)) }
    }

    /// gdb extension
    fn gdb_read(&mut self, buf: UntrustedRefMut<u8>, count: libc::size_t) -> Result {
        let buf = buf.validate_slice(count, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        // Limit the read to `Block::buf_capacity()`
        let count = usize::min(count, Block::buf_capacity());

        let (_, hostbuf) = c.alloc::<u8>(count).or(Err(libc::EMSGSIZE))?;
        let hostbuf = hostbuf.as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(hostbuf);

        let ret = unsafe { self.proxy(request!(SYS_ENARX_GDB_READ => host_virt, count))? };

        let result_len: usize = ret[0].into();

        if count < result_len {
            self.attacked();
        }

        let c = self.new_cursor();
        unsafe {
            c.copy_into_slice(count, buf[..result_len].as_mut())
                .or(Err(libc::EFAULT))?;
        }

        Ok(ret)
    }

    /// gdb extension
    fn gdb_peek(&mut self) -> Result {
        self.trace("gdb_peek", 0);
        unsafe { self.proxy(request!(SYS_ENARX_GDB_PEEK)) }
    }

    /// gdb extension
    fn gdb_write(&mut self, buf: UntrustedRef<u8>, count: libc::size_t) -> Result {
        //self.trace(">>>> gdb_write", 2);
        // Limit the write to `Block::buf_capacity()`
        let count = usize::min(count, Block::buf_capacity());

        let buf = buf.validate_slice(count, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();
        let (_, buf) = c.copy_from_slice(buf.as_ref()).or(Err(libc::EMSGSIZE))?;
        let buf = buf.as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(buf);

        let ret = unsafe { self.proxy(request!(SYS_ENARX_GDB_WRITE => host_virt, count))? };

        let result_len: usize = ret[0].into();

        if result_len > count {
            self.attacked()
        }

        Ok(ret)
    }
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
