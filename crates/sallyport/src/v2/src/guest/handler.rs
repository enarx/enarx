// SPDX-License-Identifier: Apache-2.0

use super::alloc::{phase, Alloc, Allocator, Collect, Commit, Committer};
use super::syscall::types::SockaddrOutput;
use super::{syscall, Call, Platform};
use crate::{item, Result};

use libc::{
    c_int, c_uint, clockid_t, gid_t, pid_t, size_t, stat, timespec, uid_t, utsname, ENOSYS,
};

pub trait Execute {
    /// Executes an arbitrary call.
    /// Examples of calls that this method can execute are:
    /// - [`syscall::Exit`]
    /// - [`syscall::Read`]
    /// - [`syscall::Write`]
    fn execute<'a, T: Call<'a>>(&mut self, call: T) -> Result<T::Collected>;

    /// Executes a supported syscall expressed as an opaque 7-word array akin to [`libc::syscall`].
    unsafe fn syscall(&mut self, registers: [usize; 7]) -> Result<[usize; 2]>;

    /// Loops infinitely trying to exit.
    fn attacked(&mut self) -> ! {
        loop {
            let _ = self.exit(1);
        }
    }

    /// Executes [`bind`](https://man7.org/linux/man-pages/man2/bind.2.html) syscall akin to [`libc::bind`].
    fn bind(&mut self, sockfd: c_int, addr: &[u8]) -> Result<()> {
        self.execute(syscall::Bind { sockfd, addr })?
    }

    /// Executes [`clock_gettime`](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) syscall akin to [`libc::clock_gettime`].
    fn clock_gettime(&mut self, clockid: clockid_t, tp: &mut timespec) -> Result<()> {
        self.execute(syscall::ClockGettime { clockid, tp })?
    }

    /// Executes [`close`](https://man7.org/linux/man-pages/man2/close.2.html) syscall akin to [`libc::close`].
    fn close(&mut self, fd: c_int) -> Result<()> {
        self.execute(syscall::Close { fd })?
    }

    /// Executes [`connect`](https://man7.org/linux/man-pages/man2/connect.2.html) syscall akin to [`libc::connect`].
    fn connect(&mut self, sockfd: c_int, addr: &[u8]) -> Result<()> {
        self.execute(syscall::Connect { sockfd, addr })?
    }

    /// Executes [`dup`](https://man7.org/linux/man-pages/man2/dup.2.html) syscall akin to [`libc::dup`].
    fn dup(&mut self, oldfd: c_int) -> Result<()> {
        self.execute(syscall::Dup { oldfd })?
    }

    /// Executes [`dup2`](https://man7.org/linux/man-pages/man2/dup2.2.html) syscall akin to [`libc::dup2`].
    fn dup2(&mut self, oldfd: c_int, newfd: c_int) -> Result<()> {
        self.execute(syscall::Dup2 { oldfd, newfd })?
    }

    /// Executes [`dup3`](https://man7.org/linux/man-pages/man2/dup3.2.html) syscall akin to [`libc::dup3`].
    fn dup3(&mut self, oldfd: c_int, newfd: c_int, flags: c_int) -> Result<()> {
        self.execute(syscall::Dup3 {
            oldfd,
            newfd,
            flags,
        })?
    }

    /// Executes [`eventfd2`](https://man7.org/linux/man-pages/man2/eventfd2.2.html).
    fn eventfd2(&mut self, initval: c_int, flags: c_int) -> Result<c_int> {
        self.execute(syscall::Eventfd2 { initval, flags })?
    }

    /// Executes [`exit`](https://man7.org/linux/man-pages/man2/exit.2.html) syscall akin to [`libc::exit`].
    fn exit(&mut self, status: c_int) -> Result<()> {
        self.execute(syscall::Exit { status })??;
        self.attacked()
    }

    /// Executes [`exit_group`](https://man7.org/linux/man-pages/man2/exit_group.2.html).
    fn exit_group(&mut self, status: c_int) -> Result<()> {
        self.execute(syscall::ExitGroup { status })??;
        self.attacked()
    }

    /// Executes [`fcntl`](https://man7.org/linux/man-pages/man2/fcntl.2.html) syscall akin to [`libc::fcntl`].
    fn fcntl(&mut self, fd: c_int, cmd: c_int, arg: c_int) -> Result<c_int> {
        self.execute(syscall::Fcntl { fd, cmd, arg })?
    }

    /// Executes [`fstat`](https://man7.org/linux/man-pages/man2/fstat.2.html) syscall akin to [`libc::fstat`].
    fn fstat(&mut self, fd: c_int, statbuf: &mut stat) -> Result<()> {
        self.execute(syscall::Fstat { fd, statbuf })?
    }

    /// Executes [`getegid`](https://man7.org/linux/man-pages/man2/getegid.2.html) syscall akin to [`libc::getegid`].
    fn getegid(&mut self) -> Result<gid_t> {
        self.execute(syscall::Getegid)
    }

    /// Executes [`geteuid`](https://man7.org/linux/man-pages/man2/geteuid.2.html) syscall akin to [`libc::geteuid`].
    fn geteuid(&mut self) -> Result<uid_t> {
        self.execute(syscall::Geteuid)
    }

    /// Executes [`getgid`](https://man7.org/linux/man-pages/man2/getgid.2.html) syscall akin to [`libc::getgid`].
    fn getgid(&mut self) -> Result<gid_t> {
        self.execute(syscall::Getgid)
    }

    /// Executes [`getpid`](https://man7.org/linux/man-pages/man2/getpid.2.html) syscall akin to [`libc::getpid`].
    fn getpid(&mut self) -> Result<pid_t> {
        self.execute(syscall::Getpid)
    }

    /// Executes [`getrandom`](https://man7.org/linux/man-pages/man2/getrandom.2.html) syscall akin to [`libc::getrandom`].
    fn getrandom(&mut self, buf: &mut [u8], flags: c_uint) -> Result<size_t> {
        self.execute(syscall::Getrandom { buf, flags })?
    }

    /// Executes [`getsockname`](https://man7.org/linux/man-pages/man2/getsockname.2.html) syscall akin to [`libc::getsockname`].
    fn getsockname(&mut self, sockfd: c_int, addr: SockaddrOutput) -> Result<()> {
        self.execute(syscall::Getsockname { sockfd, addr })?
    }

    /// Executes [`getuid`](https://man7.org/linux/man-pages/man2/getuid.2.html) syscall akin to [`libc::getuid`].
    fn getuid(&mut self) -> Result<uid_t> {
        self.execute(syscall::Getuid)
    }

    /// Executes [`listen`](https://man7.org/linux/man-pages/man2/listen.2.html) syscall akin to [`libc::listen`].
    fn listen(&mut self, sockfd: c_int, backlog: c_int) -> Result<()> {
        self.execute(syscall::Listen { sockfd, backlog })?
    }

    /// Executes [`read`](https://man7.org/linux/man-pages/man2/read.2.html) syscall akin to [`libc::read`].
    fn read(&mut self, fd: c_int, buf: &mut [u8]) -> Result<size_t> {
        self.execute(syscall::Read { fd, buf })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`setsockopt`](https://man7.org/linux/man-pages/man2/setsockopt.2.html) syscall akin to [`libc::setsockopt`].
    fn setsockopt(
        &mut self,
        sockfd: c_int,
        level: c_int,
        optname: c_int,
        optval: &[u8],
    ) -> Result<c_int> {
        self.execute(syscall::Setsockopt {
            sockfd,
            level,
            optname,
            optval,
        })?
    }

    /// Executes [`socket`](https://man7.org/linux/man-pages/man2/socket.2.html) syscall akin to [`libc::socket`].
    fn socket(&mut self, domain: c_int, typ: c_int, protocol: c_int) -> Result<c_int> {
        self.execute(syscall::Socket {
            domain,
            typ,
            protocol,
        })?
    }

    /// Executes [`sync`](https://man7.org/linux/man-pages/man2/sync.2.html) syscall akin to [`libc::sync`].
    fn sync(&mut self) -> Result<()> {
        self.execute(syscall::Sync)?
    }

    /// Executes [`uname`](https://man7.org/linux/man-pages/man2/uname.2.html) syscall akin to [`libc::uname`].
    fn uname(&mut self, buf: &mut utsname) -> Result<()> {
        self.execute(syscall::Uname { buf })?
    }

    /// Executes [`write`](https://man7.org/linux/man-pages/man2/write.2.html) syscall akin to [`libc::write`].
    fn write(&mut self, fd: c_int, buf: &[u8]) -> Result<size_t> {
        self.execute(syscall::Write { fd, buf })?
            .unwrap_or_else(|| self.attacked())
    }
}

/// Guest request handler.
pub struct Handler<'a, P: Platform> {
    alloc: Alloc<'a, phase::Init>,
    platform: P,
}

impl<'a, P: Platform> Handler<'a, P> {
    /// Creates a new [`Handler`] given a mutable borrow of the sallyport block and a [`Platform`].
    pub fn new(block: &'a mut [usize], platform: P) -> Self {
        Self {
            alloc: Alloc::new(block),
            platform,
        }
    }
}

impl<'a, P: Platform> Execute for Handler<'a, P> {
    fn execute<'b, T: Call<'b>>(&mut self, call: T) -> Result<T::Collected> {
        let mut alloc = self.alloc.stage();
        let ((call, len), mut end_ref) =
            alloc.reserve_input(|alloc| alloc.section(|alloc| call.stage(alloc)))?;

        let alloc = alloc.commit();
        let call = call.commit(&alloc);
        if len > 0 {
            end_ref.copy_from(
                &alloc,
                item::Header {
                    kind: item::Kind::End,
                    size: 0,
                },
            );
            self.platform.sally()?;
        }

        let alloc = alloc.collect();
        Ok(call.collect(&alloc))
    }

    unsafe fn syscall(&mut self, registers: [usize; 7]) -> Result<[usize; 2]> {
        let [num, argv @ ..] = registers;
        match (num as _, argv) {
            (libc::SYS_bind, [sockfd, addr, addrlen, ..]) => {
                let addr = self.platform.validate_slice(addr, addrlen)?;
                self.bind(sockfd as _, addr).map(|_| [0, 0])
            }
            (libc::SYS_clock_gettime, [clockid, tp, ..]) => {
                let tp = self.platform.validate_mut(tp)?;
                self.clock_gettime(clockid as _, tp).map(|_| [0, 0])
            }
            (libc::SYS_close, [fd, ..]) => self.close(fd as _).map(|_| [0, 0]),
            (libc::SYS_connect, [sockfd, addr, addrlen, ..]) => {
                let addr = self.platform.validate_slice(addr, addrlen)?;
                self.connect(sockfd as _, addr).map(|_| [0, 0])
            }
            (libc::SYS_dup, [oldfd, ..]) => self.dup(oldfd as _).map(|_| [0, 0]),
            (libc::SYS_dup2, [oldfd, newfd, ..]) => {
                self.dup2(oldfd as _, newfd as _).map(|_| [0, 0])
            }
            (libc::SYS_dup3, [oldfd, newfd, flags, ..]) => self
                .dup3(oldfd as _, newfd as _, flags as _)
                .map(|_| [0, 0]),
            (libc::SYS_eventfd2, [initval, flags, ..]) => self
                .eventfd2(initval as _, flags as _)
                .map(|ret| [ret as _, 0]),
            (libc::SYS_exit, [status, ..]) => self.exit(status as _).map(|_| self.attacked()),
            (libc::SYS_exit_group, [status, ..]) => {
                self.exit_group(status as _).map(|_| self.attacked())
            }
            (libc::SYS_fcntl, [fd, cmd, arg, ..]) => self
                .fcntl(fd as _, cmd as _, arg as _)
                .map(|ret| [ret as _, 0]),
            (libc::SYS_fstat, [fd, statbuf, ..]) => {
                let statbuf = self.platform.validate_mut(statbuf)?;
                self.fstat(fd as _, statbuf).map(|_| [0, 0])
            }
            (libc::SYS_getegid, ..) => self.getegid().map(|ret| [ret as _, 0]),
            (libc::SYS_geteuid, ..) => self.geteuid().map(|ret| [ret as _, 0]),
            (libc::SYS_getgid, ..) => self.getgid().map(|ret| [ret as _, 0]),
            (libc::SYS_getpid, ..) => self.getpid().map(|ret| [ret as _, 0]),
            (libc::SYS_getrandom, [buf, buflen, flags, ..]) => {
                let buf = self.platform.validate_slice_mut(buf, buflen)?;
                self.getrandom(buf, flags as _).map(|ret| [ret as _, 0])
            }
            (libc::SYS_getsockname, [sockfd, addr, addrlen, ..]) => {
                let addrlen = self.platform.validate_mut(addrlen)?;
                let addr = self.platform.validate_slice_mut(addr, *addrlen as _)?;
                self.getsockname(sockfd as _, SockaddrOutput::new(addr, addrlen))
                    .map(|_| [0, 0])
            }
            (libc::SYS_getuid, ..) => self.getuid().map(|ret| [ret as _, 0]),
            (libc::SYS_listen, [sockfd, backlog, ..]) => {
                self.listen(sockfd as _, backlog as _).map(|_| [0, 0])
            }
            (libc::SYS_read, [fd, buf, count, ..]) => {
                let buf = self.platform.validate_slice_mut(buf, count)?;
                self.read(fd as _, buf).map(|ret| [ret, 0])
            }
            (libc::SYS_setsockopt, [sockfd, level, optname, optval, optlen, ..]) => {
                let optval = self.platform.validate_slice(optval, optlen)?;
                self.setsockopt(sockfd as _, level as _, optname as _, optval)
                    .map(|ret| [ret as _, 0])
            }
            (libc::SYS_socket, [domain, typ, protocol, ..]) => self
                .socket(domain as _, typ as _, protocol as _)
                .map(|ret| [ret as _, 0]),
            (libc::SYS_sync, ..) => self.sync().map(|_| [0, 0]),
            (libc::SYS_uname, [buf, ..]) => {
                let buf = self.platform.validate_mut(buf)?;
                self.uname(buf).map(|_| [0, 0])
            }
            (libc::SYS_write, [fd, buf, count, ..]) => {
                let buf = self.platform.validate_slice(buf, count)?;
                self.write(fd as _, buf).map(|ret| [ret, 0])
            }
            _ => Err(ENOSYS),
        }
    }
}
