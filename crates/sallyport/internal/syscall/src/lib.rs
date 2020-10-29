// SPDX-License-Identifier: Apache-2.0

//! Common syscall handling across shims

#![deny(missing_docs)]
#![deny(clippy::all)]
#![cfg_attr(not(test), no_std)]

use core::convert::TryInto;
use core::mem::MaybeUninit;
use primordial::Register;
use sallyport::{request, Cursor, Request, Result};
use untrusted::{AddressValidator, UntrustedRef, UntrustedRefMut, Validate, ValidateSlice};

/// `get_attestation` syscall number
///
/// See https://github.com/enarx/enarx-keepldr/issues/31
pub const SYS_GETATT: i64 = 0xEA01;

/// `get_attestation` technology return value
///
/// See https://github.com/enarx/enarx-keepldr/issues/31
pub const SEV_TECH: usize = 1;

/// `get_attestation` technology return value
///
/// See https://github.com/enarx/enarx-keepldr/issues/31
pub const SGX_TECH: usize = 2;

// arch_prctl syscalls not available in the libc crate as of version 0.2.69
/// missing in libc
pub const ARCH_SET_GS: libc::c_int = 0x1001;
/// missing in libc
pub const ARCH_SET_FS: libc::c_int = 0x1002;
/// missing in libc
pub const ARCH_GET_FS: libc::c_int = 0x1003;
/// missing in libc
pub const ARCH_GET_GS: libc::c_int = 0x1004;

/// Fake uid returned by enarx
pub const FAKE_UID: usize = 1000;
/// Fake gid returned by enarx
pub const FAKE_GID: usize = 1000;

/// not defined in libc
///
/// FIXME
pub struct KernelSigSet;

type KernelSigAction = [u64; 4];

/// A trait defining a shim syscall handler
///
/// Implemented for each shim. Some common methods are already implemented,
/// but can be overwritten with optimized versions.
pub trait SyscallHandler: AddressValidator + Sized {
    /// Proxy a syscall `Request`
    ///
    /// # Safety
    /// The caller has to ensure valid parameters.
    unsafe fn proxy(&mut self, req: Request) -> Result;

    /// Called, when the host might want to attack us, giving
    /// the shim bogus values
    fn attacked(&mut self) -> !;

    /// Translates a shim virtual address to the host virtual address
    fn translate_shim_to_host_addr<T>(&self, buf: *const T) -> *const T;

    /// Returns a new `Cursor` for the sallyport `Block`
    fn new_cursor(&mut self) -> Cursor;

    /// Output tracing information about the syscall
    fn trace(&mut self, name: &str, argc: usize);

    /// Enarx syscall - get attestation
    fn get_attestation(&mut self) -> Result;

    /// syscall
    fn exit(&mut self, status: libc::c_int) -> !;

    /// syscall
    fn exit_group(&mut self, status: libc::c_int) -> !;

    /// syscall
    fn arch_prctl(&mut self, code: libc::c_int, addr: libc::c_ulong) -> Result;

    /// syscall
    fn mprotect(&mut self, addr: UntrustedRef<u8>, len: libc::size_t, prot: libc::c_int) -> Result;

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

    /// Do a munmap() syscall
    ///
    /// This is currently unimplemented and returns success.
    fn munmap(&mut self, addr: UntrustedRef<u8>, lenght: libc::size_t) -> Result;

    /// syscall
    fn brk(&mut self, addr: *const u8) -> Result;

    /// syscall
    fn madvise(
        &mut self,
        addr: *const libc::c_void,
        length: libc::size_t,
        advice: libc::c_int,
    ) -> Result;

    /// syscall
    #[allow(clippy::too_many_arguments)]
    fn syscall(
        &mut self,
        a: Register<usize>,
        b: Register<usize>,
        c: Register<usize>,
        d: Register<usize>,
        e: Register<usize>,
        f: Register<usize>,
        nr: usize,
    ) -> Result {
        let mut ret = match nr as _ {
            libc::SYS_exit => self.exit(usize::from(a) as _),
            libc::SYS_exit_group => self.exit_group(usize::from(a) as _),
            libc::SYS_read => self.read(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_readv => self.readv(usize::from(a) as _, b.into(), usize::from(c) as _),
            libc::SYS_write => self.write(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_writev => self.writev(usize::from(a) as _, b.into(), usize::from(c) as _),
            libc::SYS_mmap => self.mmap(
                a.into(),
                b.into(),
                c.try_into().map_err(|_| libc::EINVAL)?,
                usize::from(d) as _,
                usize::from(e) as _,
                f.into(),
            ),
            libc::SYS_munmap => self.munmap(a.into(), b.into()),
            libc::SYS_arch_prctl => self.arch_prctl(usize::from(a) as _, b.into()),
            libc::SYS_set_tid_address => self.set_tid_address(a.into()),
            libc::SYS_rt_sigaction => {
                self.rt_sigaction(usize::from(a) as _, b.into(), c.into(), d.into())
            }
            libc::SYS_rt_sigprocmask => {
                self.rt_sigprocmask(usize::from(a) as _, b.into(), c.into(), d.into())
            }
            libc::SYS_sigaltstack => self.sigaltstack(a.into(), b.into()),
            libc::SYS_getrandom => self.getrandom(a.into(), b.into(), usize::from(c) as _),
            libc::SYS_brk => self.brk(a.into()),
            libc::SYS_ioctl => self.ioctl(usize::from(a) as _, b.into()),
            libc::SYS_mprotect => self.mprotect(a.into(), b.into(), usize::from(c) as _),
            libc::SYS_clock_gettime => self.clock_gettime(usize::from(a) as _, b.into()),
            libc::SYS_uname => self.uname(a.into()),
            libc::SYS_readlink => self.readlink(a.into(), b.into(), c.into()),
            libc::SYS_fstat => self.fstat(usize::from(a) as _, b.into()),
            libc::SYS_fcntl => self.fcntl(usize::from(a) as _, usize::from(b) as _),
            libc::SYS_madvise => self.madvise(a.into(), b.into(), usize::from(c) as _),
            libc::SYS_poll => self.poll(a.into(), b.into(), usize::from(c) as _),
            libc::SYS_getuid => self.getuid(),
            libc::SYS_getgid => self.getgid(),
            libc::SYS_geteuid => self.geteuid(),
            libc::SYS_getegid => self.getegid(),

            SYS_GETATT => self.get_attestation(),

            _ => Err(libc::ENOSYS),
        };

        #[cfg(target_arch = "x86_64")]
        if nr < 0xEA00 {
            // Non Enarx syscalls don't use `ret[1]` and have
            // to return the original value of `rdx`.
            ret = ret.map(|ret| [ret[0], c]);
        }

        ret
    }

    /// syscall
    fn read(&mut self, fd: libc::c_int, buf: UntrustedRefMut<u8>, count: libc::size_t) -> Result {
        self.trace("read", 4);

        let buf = buf.validate_slice(count, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        let (_, hostbuf) = c.alloc::<u8>(count).or(Err(libc::EMSGSIZE))?;
        let hostbuf = hostbuf.as_ptr();
        let host_virt = self.translate_shim_to_host_addr(hostbuf);

        let ret = unsafe { self.proxy(request!(libc::SYS_read => fd, host_virt, count))? };

        let result_len: usize = ret[0].into();

        if count < result_len {
            self.attacked();
        }

        let c = self.new_cursor();
        c.copy_into_slice(count, buf.as_mut(), result_len)
            .or(Err(libc::EFAULT))?;

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
        let buf = buf.validate_slice(count, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();
        let (_, buf) = c.copy_from_slice(buf.as_ref()).or(Err(libc::EMSGSIZE))?;
        let buf = buf.as_ptr();
        let host_virt = self.translate_shim_to_host_addr(buf);

        let ret = unsafe { self.proxy(request!(libc::SYS_write => fd, host_virt, count))? };
        Ok(ret)
    }

    /// syscall
    fn writev(
        &mut self,
        fd: libc::c_int,
        iovec: UntrustedRef<libc::iovec>,
        iovcnt: libc::c_int,
    ) -> Result {
        let iovec = iovec.validate_slice(iovcnt, self).ok_or(libc::EFAULT)?;

        let mut size = 0usize;

        for vec in iovec {
            size +=
                usize::from(self.write(fd, (vec.iov_base as *const u8).into(), vec.iov_len)?[0]);
        }

        Ok([size.into(), 0.into()])
    }

    /// syscall
    fn ioctl(&mut self, fd: libc::c_int, request: libc::c_ulong) -> Result {
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
            _ => {
                //eprintln!("SC> ioctl({}, {}), … = -EBADFD", fd, request);
                Err(libc::EBADFD)
            }
        }
    }
    /// Do a set_tid_address() syscall
    ///
    /// This is currently unimplemented and returns a dummy thread id.
    fn set_tid_address(&mut self, _tidptr: *const libc::c_int) -> Result {
        // FIXME
        //eprintln!("SC> set_tid_address(…) = 1");
        Ok([1.into(), 0.into()])
    }

    /// Do a rt_sigaction() system call
    ///
    /// We don't support signals yet. So, fake success.
    fn rt_sigaction(
        &mut self,
        signum: libc::c_int,
        act: UntrustedRef<KernelSigAction>,
        oldact: UntrustedRefMut<KernelSigAction>,
        size: usize,
    ) -> Result {
        self.trace("rt_sigaction", 4);

        const SIGRTMAX: libc::c_int = 64; // TODO: add to libc crate
        static mut ACTIONS: [KernelSigAction; SIGRTMAX as usize] = [[0; 4]; SIGRTMAX as usize];

        if signum >= SIGRTMAX || size != 8 {
            return Err(libc::EINVAL);
        }

        unsafe {
            if !oldact.as_ptr().is_null() {
                let oldact = oldact.validate(self).ok_or(libc::EFAULT)?;
                *(oldact) = ACTIONS[signum as usize];
            }

            if !act.as_ptr().is_null() {
                let act = act.validate(self).ok_or(libc::EFAULT)?;
                ACTIONS[signum as usize] = *act;
            }
        }

        Ok(Default::default())
    }
    /// Do a rt_sigprocmask() syscall
    ///
    /// We don't support signals yet. So, fake success.
    fn rt_sigprocmask(
        &mut self,
        _how: libc::c_int,
        _set: UntrustedRef<KernelSigSet>,
        _oldset: UntrustedRefMut<KernelSigSet>,
        _sigsetsize: libc::size_t,
    ) -> Result {
        // FIXME
        self.trace("rt_sigprocmask", 4);
        Ok(Default::default())
    }

    /// Do a sigaltstack() syscall
    ///
    /// This is currently unimplemented and returns success.
    fn sigaltstack(
        &mut self,
        _ss: UntrustedRef<libc::stack_t>,
        _old_ss: UntrustedRefMut<libc::stack_t>,
    ) -> Result {
        self.trace("sigaltstack", 2);

        Ok(Default::default())
    }

    /// Do a getrandom() syscall
    fn getrandom(
        &mut self,
        buf: UntrustedRefMut<u8>,
        buflen: libc::size_t,
        flags: libc::c_uint,
    ) -> Result {
        let flags = flags & !(libc::GRND_NONBLOCK | libc::GRND_RANDOM);

        if flags != 0 {
            return Err(libc::EINVAL);
        }

        let trusted = buf.validate_slice(buflen, self).ok_or(libc::EFAULT)?;

        for (i, chunk) in trusted.chunks_mut(8).enumerate() {
            let mut el = 0u64;
            loop {
                if unsafe { core::arch::x86_64::_rdrand64_step(&mut el) } == 1 {
                    chunk.copy_from_slice(&el.to_ne_bytes()[..chunk.len()]);
                    break;
                } else {
                    if (flags & libc::GRND_NONBLOCK) != 0 {
                        //eprintln!("SC> getrandom(…) = -EAGAIN");
                        return Err(libc::EAGAIN);
                    }
                    if (flags & libc::GRND_RANDOM) != 0 {
                        //eprintln!("SC> getrandom(…) = {}", i.checked_mul(8).unwrap());
                        return Ok([i.checked_mul(8).unwrap().into(), 0.into()]);
                    }
                }
            }
        }
        //eprintln!("SC> getrandom(…) = {}", trusted.len());

        Ok([trusted.len().into(), 0.into()])
    }

    /// syscall
    fn clock_gettime(
        &mut self,
        clockid: libc::clockid_t,
        tp: UntrustedRefMut<libc::timespec>,
    ) -> Result {
        self.trace("clock_gettime", 2);
        let c = self.new_cursor();

        let (_, buf) = c.alloc::<libc::timespec>(1).or(Err(libc::EMSGSIZE))?;
        let buf = buf.as_ptr();
        let host_virt = self.translate_shim_to_host_addr(buf);

        let result =
            unsafe { self.proxy(request!(libc::SYS_clock_gettime => clockid, host_virt))? };

        let c = self.new_cursor();
        *(tp.validate(self).ok_or(libc::EFAULT)?) = unsafe { c.read().or(Err(libc::EMSGSIZE))?.1 };

        Ok(result)
    }

    /// Do a uname() system call
    fn uname(&mut self, buf: UntrustedRefMut<libc::utsname>) -> Result {
        self.trace("uname", 1);

        fn fill(buf: &mut [i8; 65], with: &str) {
            let src = with.as_bytes();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = *src.get(i).unwrap_or(&0) as i8;
            }
        }

        let u = buf.validate(self).ok_or(libc::EFAULT)?;
        fill(&mut u.sysname, "Linux");
        fill(&mut u.nodename, "localhost.localdomain");
        fill(&mut u.release, "5.6.0");
        fill(&mut u.version, "#1");
        fill(&mut u.machine, "x86_64");

        Ok(Default::default())
    }

    /// syscall
    fn readlink(
        &mut self,
        pathname: UntrustedRef<u8>,
        buf: UntrustedRefMut<u8>,
        bufsize: libc::size_t,
    ) -> Result {
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
    fn fcntl(&self, fd: libc::c_int, cmd: libc::c_int) -> Result {
        match (fd, cmd) {
            (libc::STDIN_FILENO, libc::F_GETFL) => {
                //eprintln!("SC> fcntl({}, F_GETFD) = 0x402 (flags O_RDWR|O_APPEND)", fd);
                Ok([(libc::O_RDWR | libc::O_APPEND).into(), 0.into()])
            }
            (libc::STDOUT_FILENO, libc::F_GETFL) | (libc::STDERR_FILENO, libc::F_GETFL) => {
                //eprintln!("SC> fcntl({}, F_GETFD) = 0x1 (flags O_WRONLY)", fd);
                Ok([libc::O_WRONLY.into(), 0.into()])
            }
            (libc::STDIN_FILENO, _) | (libc::STDOUT_FILENO, _) | (libc::STDERR_FILENO, _) => {
                //eprintln!("SC> fcntl({}, {}) = -EINVAL", fd, cmd);
                Err(libc::EINVAL)
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
        let host_virt = self.translate_shim_to_host_addr(buf);

        let result = unsafe { self.proxy(request!(libc::SYS_poll => host_virt, nfds, timeout))? };

        let c = self.new_cursor();

        c.copy_into_slice(nfds as _, fds, nfds as _)
            .or(Err(libc::EMSGSIZE))?;

        Ok(result)
    }

    /// Do a getuid() syscall
    fn getuid(&mut self) -> Result {
        self.trace("getuid", 0);
        Ok([FAKE_UID.into(), 0.into()])
    }

    /// Do a getgid() syscall
    fn getgid(&mut self) -> Result {
        self.trace("getgid", 0);
        Ok([FAKE_GID.into(), 0.into()])
    }

    /// Do a geteuid() syscall
    fn geteuid(&mut self) -> Result {
        self.trace("geteuid", 0);
        Ok([FAKE_UID.into(), 0.into()])
    }

    /// Do a getegid() syscall
    fn getegid(&mut self) -> Result {
        self.trace("getegid", 0);
        Ok([FAKE_GID.into(), 0.into()])
    }

    /// Do close syscall
    fn close(&mut self, fd: libc::c_int) -> Result {
        self.trace("close", 1);
        unsafe { self.proxy(request!(libc::SYS_close => fd)) }
    }
}
