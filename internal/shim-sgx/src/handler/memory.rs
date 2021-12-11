// SPDX-License-Identifier: Apache-2.0

use sallyport::syscall::{BaseSyscallHandler, MemorySyscallHandler};
use sallyport::untrusted::UntrustedRef;

impl<'a> MemorySyscallHandler for super::Handler<'a> {
    /// Do a brk() system call
    fn brk(&mut self, addr: *const u8) -> sallyport::Result {
        self.trace("brk", 1);

        let ret = crate::heap::HEAP.write().brk(addr as _);
        Ok([ret.into(), Default::default()])
    }

    /// Do a mprotect() system call
    // Until EDMM, we can't change any page permissions.
    // What you get is what you get. Fake success.
    fn mprotect(
        &mut self,
        _addr: UntrustedRef<'_, u8>,
        _len: libc::size_t,
        _prot: libc::c_int,
    ) -> sallyport::Result {
        self.trace("mprotect", 3);

        Ok(Default::default())
    }

    /// Do a mmap() system call
    fn mmap(
        &mut self,
        addr: UntrustedRef<'_, u8>,
        length: libc::size_t,
        prot: libc::c_int,
        flags: libc::c_int,
        fd: libc::c_int,
        offset: libc::off_t,
    ) -> sallyport::Result {
        self.trace("mmap", 6);

        let ret = crate::heap::HEAP.write().mmap::<libc::c_void>(
            addr.as_ptr() as _,
            length,
            prot,
            flags,
            fd, // Allow truncation!
            offset,
        )?;

        Ok([ret.into(), Default::default()])
    }

    /// Do a munmap() system call
    fn munmap(&mut self, addr: UntrustedRef<'_, u8>, length: libc::size_t) -> sallyport::Result {
        self.trace("munmap", 2);

        crate::heap::HEAP
            .write()
            .munmap::<libc::c_void>(addr.as_ptr() as _, length)?;
        Ok(Default::default())
    }

    // Do madvise syscall
    // We don't actually support this. So, fake success.
    fn madvise(
        &mut self,
        _addr: *const libc::c_void,
        _length: libc::size_t,
        _advice: libc::c_int,
    ) -> sallyport::Result {
        self.trace("madvise", 3);
        Ok(Default::default())
    }
}
