// SPDX-License-Identifier: Apache-2.0

use sallyport::request;
use sallyport::syscall::{BaseSyscallHandler, FileSyscallHandler};
use sallyport::untrusted::{UntrustedRef, ValidateSlice};

impl<'a> FileSyscallHandler for super::Handler<'a> {
    /// Do a readv() syscall
    fn readv(
        &mut self,
        fd: libc::c_int,
        iovec: UntrustedRef<libc::iovec>,
        iovcnt: libc::c_int,
    ) -> sallyport::Result {
        self.trace("readv", 3);

        let mut size = 0usize;
        let trusted = iovec.validate_slice(iovcnt, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        let (c, untrusted) = c
            .copy_from_slice::<libc::iovec>(trusted)
            .or(Err(libc::EMSGSIZE))?;

        let mut c = c;
        for (t, u) in trusted.iter().zip(untrusted.iter_mut()) {
            let (nc, us) = c.alloc::<u8>(t.iov_len).or(Err(libc::EMSGSIZE))?;
            c = nc;
            u.iov_base = us.as_mut_ptr() as _;
            size += u.iov_len;
        }

        let req = request!(libc::SYS_readv => fd, untrusted, untrusted.len());
        let ret = unsafe { self.proxy(req)? };

        let mut read = ret[0].into();
        if size < read {
            self.attacked();
        }

        let c = self.new_cursor();
        let (c, _) = c
            .alloc::<libc::iovec>(trusted.len())
            .or(Err(libc::EMSGSIZE))?;

        let mut c = c;
        for t in trusted.iter() {
            let ts = t.iov_base as *mut u8;
            let ts_len: usize = t.iov_len;

            let sz = core::cmp::min(ts_len, read);

            let nc = unsafe { c.copy_into_raw_parts(ts_len, ts, sz) }.or(Err(libc::EMSGSIZE))?;
            c = nc;

            read -= sz;
        }

        Ok(ret)
    }

    /// Do a writev() syscall
    fn writev(
        &mut self,
        fd: libc::c_int,
        iovec: UntrustedRef<libc::iovec>,
        iovcnt: libc::c_int,
    ) -> sallyport::Result {
        self.trace("writev", 3);

        let mut size = 0usize;
        let trusted = iovec.validate_slice(iovcnt, self).ok_or(libc::EFAULT)?;
        let c = self.new_cursor();
        let (c, untrusted) = c
            .copy_from_slice::<libc::iovec>(trusted)
            .or(Err(libc::EMSGSIZE))?;

        let mut c = c;
        for (t, mut u) in trusted.iter().zip(untrusted.iter_mut()) {
            let (nc, us) = unsafe { c.copy_from_raw_parts(t.iov_base as *const u8, t.iov_len) }
                .or(Err(libc::EMSGSIZE))?;
            c = nc;
            u.iov_base = us as _;
            size += u.iov_len;
        }

        let req = request!(libc::SYS_writev => fd, untrusted, untrusted.len());
        let ret = unsafe { self.proxy(req)? };

        if size < ret[0].into() {
            self.attacked();
        }

        Ok(ret)
    }
}
