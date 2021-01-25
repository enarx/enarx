// SPDX-License-Identifier: Apache-2.0

//! file syscalls

use crate::BaseSyscallHandler;
use core::mem::MaybeUninit;
use sallyport::{request, Block, Result};
use untrusted::{AddressValidator, UntrustedRef, UntrustedRefMut, Validate, ValidateSlice};

/// file syscalls
pub trait FileSyscallHandler: BaseSyscallHandler + AddressValidator + Sized {
    /// syscall
    fn close(&mut self, fd: libc::c_int) -> Result {
        self.trace("close", 1);
        let ret = unsafe { self.proxy(request!(libc::SYS_close => fd))? };
        Ok(ret)
    }

    /// syscall
    fn read(&mut self, fd: libc::c_int, buf: UntrustedRefMut<u8>, count: libc::size_t) -> Result {
        self.trace("read", 4);

        let buf = buf.validate_slice(count, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        // Limit the read to `Block::buf_capacity()`
        let count = usize::min(count, Block::buf_capacity());

        let (_, hostbuf) = c.alloc::<u8>(count).or(Err(libc::EMSGSIZE))?;
        let hostbuf = hostbuf.as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(hostbuf);

        let ret = unsafe { self.proxy(request!(libc::SYS_read => fd, host_virt, count))? };

        let result_len: usize = ret[0].into();

        if count < result_len {
            self.attacked();
        }

        let c = self.new_cursor();
        unsafe {
            c.copy_into_slice(count, &mut buf[..result_len].as_mut())
                .or(Err(libc::EFAULT))?;
        }

        Ok(ret)
    }

    /// syscall
    fn readv(
        &mut self,
        fd: libc::c_int,
        iovec: UntrustedRef<libc::iovec>,
        iovcnt: libc::c_int,
    ) -> Result {
        self.trace("readv", 3);
        // FIXME: this is not an ideal implementation of readv, but for the sake
        // of simplicity this readv implementation behaves very much like how the
        // Linux kernel would for a module that does not support readv, but does
        // support read.
        let mut bytes_read = 0usize;
        for vec in iovec.validate_slice(iovcnt, self).ok_or(libc::EFAULT)? {
            let r = self.read(fd, (vec.iov_base as *mut u8).into(), vec.iov_len as _)?;
            bytes_read = bytes_read.checked_add(r[0].into()).unwrap();
        }

        Ok([bytes_read.into(), 0.into()])
    }

    /// syscall
    fn write(&mut self, fd: libc::c_int, buf: UntrustedRef<u8>, count: libc::size_t) -> Result {
        // No trace for write, if fd is stdout or stderr, or our own debug will be clobbered
        if fd != libc::STDOUT_FILENO && fd != libc::STDERR_FILENO {
            self.trace("write", 3);
        }

        // Limit the write to `Block::buf_capacity()`
        let count = usize::min(count, Block::buf_capacity());

        let buf = buf.validate_slice(count, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();
        let (_, buf) = c.copy_from_slice(buf.as_ref()).or(Err(libc::EMSGSIZE))?;
        let buf = buf.as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(buf);

        let ret = unsafe { self.proxy(request!(libc::SYS_write => fd, host_virt, count))? };

        let result_len: usize = ret[0].into();

        if result_len > count {
            self.attacked()
        }

        Ok(ret)
    }

    /// syscall
    fn writev(
        &mut self,
        fd: libc::c_int,
        iovec: UntrustedRef<libc::iovec>,
        iovcnt: libc::c_int,
    ) -> Result {
        self.trace("writev", 3);
        let iovec = iovec.validate_slice(iovcnt, self).ok_or(libc::EFAULT)?;

        let mut size = 0usize;

        for vec in iovec {
            let written =
                usize::from(self.write(fd, (vec.iov_base as *const u8).into(), vec.iov_len)?[0]);

            if written > vec.iov_len {
                self.attacked();
            }

            size += written;

            if written != vec.iov_len {
                // There was a short write, let userspace retry.
                break;
            }
        }

        Ok([size.into(), 0.into()])
    }

    /// syscall
    fn ioctl(&mut self, fd: libc::c_int, request: libc::c_ulong, arg: usize) -> Result {
        self.trace("ioctl", 3);
        match (fd as _, request as _) {
            (libc::STDIN_FILENO, libc::TIOCGWINSZ)
            | (libc::STDOUT_FILENO, libc::TIOCGWINSZ)
            | (libc::STDERR_FILENO, libc::TIOCGWINSZ) => {
                // the keep has no tty
                //eprintln!("SC> ioctl({}, TIOCGWINSZ, … = -ENOTTY", fd);
                Err(libc::ENOTTY)
            }
            (libc::STDIN_FILENO, _) | (libc::STDOUT_FILENO, _) | (libc::STDERR_FILENO, _) => {
                //eprintln!("SC> ioctl({}, {}), … = -EINVAL", fd, request);
                Err(libc::EINVAL)
            }
            (_, libc::FIONBIO) => unsafe {
                let val = UntrustedRef::from(arg as *const libc::c_int)
                    .validate(self)
                    .ok_or(libc::EFAULT)?;
                let c = self.new_cursor();
                let (_, buf) = c.write(val).or(Err(libc::EMSGSIZE))?;
                let host_virt = Self::translate_shim_to_host_addr(buf);

                self.proxy(request!(libc::SYS_ioctl => fd, request, host_virt))
            },
            _ => {
                //eprintln!("SC> ioctl({}, {}), … = -EBADFD", fd, request);
                Err(libc::EBADFD)
            }
        }
    }

    /// syscall
    fn readlink(
        &mut self,
        pathname: UntrustedRef<u8>,
        buf: UntrustedRefMut<u8>,
        bufsize: libc::size_t,
    ) -> Result {
        self.trace("readlink", 3);
        // Fake readlink("/proc/self/exe")
        const PROC_SELF_EXE: &str = "/proc/self/exe";

        let pathname = unsafe {
            let mut len: isize = 0;
            let ptr: *const u8 = pathname.validate(self).ok_or(libc::EFAULT)? as _;
            loop {
                if ptr.offset(len).read() == 0 {
                    break;
                }
                len = len.checked_add(1).unwrap();
                if len as usize >= PROC_SELF_EXE.len() {
                    break;
                }
            }
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len as _))
        };

        if !pathname.eq(PROC_SELF_EXE) {
            return Err(libc::ENOENT);
        }

        if bufsize < 6 {
            return Err(libc::EINVAL);
        }

        let buf = buf.validate_slice(bufsize, self).ok_or(libc::EFAULT)?;
        buf[..6].copy_from_slice(b"/init\0");
        //eprintln!("SC> readlink({:#?}, \"/init\", {}) = 5", pathname, bufsize);
        Ok([5.into(), 0.into()])
    }

    /// syscall
    fn fstat(&mut self, fd: libc::c_int, statbuf: UntrustedRefMut<libc::stat>) -> Result {
        self.trace("fstat", 2);
        // Fake fstat(0|1|2, ...) done by glibc or rust
        match fd {
            libc::STDIN_FILENO | libc::STDOUT_FILENO | libc::STDERR_FILENO => {
                #[allow(clippy::integer_arithmetic)]
                const fn makedev(x: u64, y: u64) -> u64 {
                    (((x) & 0xffff_f000u64) << 32)
                        | (((x) & 0x0000_0fffu64) << 8)
                        | (((y) & 0xffff_ff00u64) << 12)
                        | ((y) & 0x0000_00ffu64)
                }

                let mut p = unsafe { MaybeUninit::<libc::stat>::zeroed().assume_init() };

                p.st_dev = makedev(
                    0,
                    match fd {
                        0 => 0x19,
                        _ => 0xc,
                    },
                );
                p.st_ino = 3;
                p.st_mode = libc::S_IFIFO | 0o600;
                p.st_nlink = 1;
                p.st_uid = 1000;
                p.st_gid = 5;
                p.st_blksize = 4096;
                p.st_blocks = 0;
                p.st_rdev = makedev(0x88, 0);
                p.st_size = 0;

                p.st_atime = 1_579_507_218 /* 2020-01-21T11:45:08.467721685+0100 */;
                p.st_atime_nsec = 0;
                p.st_mtime = 1_579_507_218 /* 2020-01-21T11:45:07.467721685+0100 */;
                p.st_mtime_nsec = 0;
                p.st_ctime = 1_579_507_218 /* 2020-01-20T09:00:18.467721685+0100 */;
                p.st_ctime_nsec = 0;

                let statbuf = statbuf.validate(self).ok_or(libc::EFAULT)?;
                *statbuf = p;

                /* eprintln!("SC> fstat({}, {{st_dev=makedev(0, 0x19), st_ino=3, st_mode=S_IFIFO|0600,\
                st_nlink=1, st_uid=1000, st_gid=5, st_blksize=4096, st_blocks=0, st_size=0,\
                 st_rdev=makedev(0x88, 0), st_atime=1579507218 /* 2020-01-21T11:45:08.467721685+0100 */,\
                  st_atime_nsec=0, st_mtime=1579507218 /* 2020-01-21T11:45:08.467721685+0100 */,\
                   st_mtime_nsec=0, st_ctime=1579507218 /* 2020-01-21T11:45:08.467721685+0100 */,\
                    st_ctime_nsec=0}}) = 0", fd);

                */
                Ok(Default::default())
            }
            _ => Err(libc::EBADF),
        }
    }

    /// syscall
    fn fcntl(&mut self, fd: libc::c_int, cmd: libc::c_int, arg: libc::c_int) -> Result {
        self.trace("fcntl", 3);
        match (fd, cmd) {
            (libc::STDIN_FILENO, libc::F_GETFL) => {
                //eprintln!("SC> fcntl({}, F_GETFL) = 0x402 (flags O_RDWR|O_APPEND)", fd);
                Ok([(libc::O_RDWR | libc::O_APPEND).into(), 0.into()])
            }
            (libc::STDOUT_FILENO, libc::F_GETFL) | (libc::STDERR_FILENO, libc::F_GETFL) => {
                //eprintln!("SC> fcntl({}, F_GETFL) = 0x1 (flags O_WRONLY)", fd);
                Ok([libc::O_WRONLY.into(), 0.into()])
            }
            (libc::STDIN_FILENO, _) | (libc::STDOUT_FILENO, _) | (libc::STDERR_FILENO, _) => {
                //eprintln!("SC> fcntl({}, {}) = -EINVAL", fd, cmd);
                Err(libc::EINVAL)
            }
            (_, libc::F_GETFD) => {
                //self.trace("fcntl", 3);
                unsafe { self.proxy(request!(libc::SYS_fcntl => fd, cmd)) }
            }
            (_, libc::F_SETFD) => {
                //self.trace("fcntl", 3);
                unsafe { self.proxy(request!(libc::SYS_fcntl => fd, cmd, arg)) }
            }
            (_, libc::F_GETFL) => {
                //self.trace("fcntl", 3);
                unsafe { self.proxy(request!(libc::SYS_fcntl => fd, cmd)) }
            }
            (_, libc::F_SETFL) => {
                //self.trace("fcntl", 3);
                unsafe { self.proxy(request!(libc::SYS_fcntl => fd, cmd, arg)) }
            }
            (_, _) => {
                //eprintln!("SC> fcntl({}, {}) = -EBADFD", fd, cmd);
                Err(libc::EBADFD)
            }
        }
    }

    /// syscall
    fn poll(
        &mut self,
        fds: UntrustedRefMut<libc::pollfd>,
        nfds: libc::nfds_t,
        timeout: libc::c_int,
    ) -> Result {
        self.trace("poll", 3);

        let fds = fds.validate_slice(nfds, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        let (_, buf) = c.copy_from_slice(fds).or(Err(libc::EMSGSIZE))?;
        let buf = buf.as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(buf);

        let result = unsafe { self.proxy(request!(libc::SYS_poll => host_virt, nfds, timeout))? };

        let c = self.new_cursor();

        unsafe {
            c.copy_into_slice(nfds as _, &mut fds[..(nfds as usize)])
                .or(Err(libc::EMSGSIZE))?;
        }

        Ok(result)
    }

    /// syscall
    fn pipe(&mut self, pipefd: UntrustedRefMut<libc::c_int>) -> Result {
        self.trace("pipe", 1);
        let pipefd = pipefd.validate_slice(2, self).ok_or(libc::EFAULT)?;
        let c = self.new_cursor();

        let (_, hostbuf) = c.alloc::<libc::c_int>(2).or(Err(libc::EMSGSIZE))?;
        let hostbuf = hostbuf.as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(hostbuf);

        let ret = unsafe { self.proxy(request!(libc::SYS_pipe => host_virt))? };

        let c = self.new_cursor();
        unsafe {
            c.copy_into_slice(2, pipefd.as_mut())
                .or(Err(libc::EFAULT))?;
        }

        Ok(ret)
    }

    /// syscall
    fn epoll_create1(&mut self, flags: libc::c_int) -> Result {
        self.trace("epoll_create1", 1);
        let ret = unsafe { self.proxy(request!(libc::SYS_epoll_create1 => flags))? };
        Ok(ret)
    }

    /// syscall
    fn epoll_ctl(
        &mut self,
        epfd: libc::c_int,
        op: libc::c_int,
        fd: libc::c_int,
        event: UntrustedRef<libc::epoll_event>,
    ) -> Result {
        self.trace("epoll_ctl", 4);

        let event = event.validate(self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();
        let (_, buf) = c.write(event).or(Err(libc::EMSGSIZE))?;
        let host_virt = Self::translate_shim_to_host_addr(buf);

        // clear sensitive user data from the event
        buf.u64 = fd as _;

        let ret = unsafe { self.proxy(request!(libc::SYS_epoll_ctl => epfd, op, fd, host_virt))? };

        Ok(ret)
    }

    /// syscall
    fn epoll_wait(
        &mut self,
        epfd: libc::c_int,
        event: UntrustedRefMut<libc::epoll_event>,
        maxevents: libc::c_int,
        timeout: libc::c_int,
    ) -> Result {
        self.trace("epoll_wait", 4);

        let maxevents: usize = maxevents as _;

        let event = event.validate_slice(maxevents, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        let (_, hostbuf) = c
            .alloc::<libc::epoll_event>(maxevents)
            .or(Err(libc::EMSGSIZE))?;
        let hostbuf = hostbuf.as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(hostbuf);

        let ret = unsafe {
            self.proxy(request!(libc::SYS_epoll_wait => epfd, host_virt, maxevents, timeout))?
        };

        let result_len: usize = ret[0].into();

        if maxevents < result_len {
            self.attacked();
        }

        let c = self.new_cursor();
        unsafe {
            c.copy_into_slice(maxevents, &mut event[..result_len])
                .or(Err(libc::EFAULT))?;
        }

        Ok(ret)
    }

    /// syscall
    fn epoll_pwait(
        &mut self,
        epfd: libc::c_int,
        event: UntrustedRefMut<libc::epoll_event>,
        maxevents: libc::c_int,
        timeout: libc::c_int,
        _sigmask: UntrustedRef<libc::sigset_t>,
    ) -> Result {
        self.epoll_wait(epfd, event, maxevents, timeout)
    }

    /// syscall
    fn eventfd2(&mut self, initval: libc::c_uint, flags: libc::c_int) -> Result {
        self.trace("eventfd2", 2);
        unsafe { self.proxy(request!(libc::SYS_eventfd2 => initval, flags)) }
    }

    /// syscall
    fn dup(&mut self, oldfd: libc::c_int) -> Result {
        self.trace("dup", 1);
        unsafe { self.proxy(request!(libc::SYS_dup => oldfd)) }
    }

    /// syscall
    fn dup2(&mut self, oldfd: libc::c_int, newfd: libc::c_int) -> Result {
        self.trace("dup2", 2);
        unsafe { self.proxy(request!(libc::SYS_dup2 => oldfd, newfd)) }
    }

    /// syscall
    fn dup3(&mut self, oldfd: libc::c_int, newfd: libc::c_int, flags: libc::c_int) -> Result {
        self.trace("dup3", 3);
        unsafe { self.proxy(request!(libc::SYS_dup3 => oldfd, newfd, flags)) }
    }
}
