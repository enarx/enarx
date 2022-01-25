// SPDX-License-Identifier: Apache-2.0

use super::alloc::{phase, Alloc, Allocator, Collect, Commit, Committer};
use super::{syscall, Call, Platform};
use crate::{item, Result};

use libc::{c_int, c_uint, gid_t, pid_t, size_t, stat, uid_t, utsname, ENOSYS};

pub trait Execute {
    type Platform: Platform;
    type Allocator: Allocator;

    fn platform(&mut self) -> &mut Self::Platform;

    fn allocator(&mut self) -> Self::Allocator;

    /// Executes an arbitrary call.
    /// Examples of calls that this method can execute are:
    /// - [`syscall::Exit`]
    /// - [`syscall::Read`]
    /// - [`syscall::Write`]
    fn execute<'a, T: Call<'a>>(&mut self, call: T) -> Result<T::Collected> {
        let mut alloc = self.allocator();
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
            self.platform().sally()?;
        }

        let alloc = alloc.collect();
        Ok(call.collect(&alloc))
    }

    /// Loops infinitely trying to exit.
    fn attacked(&mut self) -> ! {
        loop {
            let _ = self.exit(1);
        }
    }

    /// Executes a supported syscall expressed as an opaque 7-word array akin to [`libc::syscall`].
    unsafe fn syscall(&mut self, registers: [usize; 7]) -> Result<[usize; 2]> {
        let [num, argv @ ..] = registers;
        match (num as _, argv) {
            (libc::SYS_close, [fd, ..]) => self.close(fd as _).map(|_| [0, 0]),
            (libc::SYS_dup, [oldfd, ..]) => self.dup(oldfd as _).map(|_| [0, 0]),
            (libc::SYS_dup2, [oldfd, newfd, ..]) => {
                self.dup2(oldfd as _, newfd as _).map(|_| [0, 0])
            }
            (libc::SYS_dup3, [oldfd, newfd, flags, ..]) => self
                .dup3(oldfd as _, newfd as _, flags as _)
                .map(|_| [0, 0]),
            (libc::SYS_exit, [status, ..]) => self.exit(status as _).map(|_| self.attacked()),
            (libc::SYS_exit_group, [status, ..]) => {
                self.exit_group(status as _).map(|_| self.attacked())
            }
            (libc::SYS_fcntl, [fd, cmd, arg, ..]) => self
                .fcntl(fd as _, cmd as _, arg as _)
                .map(|ret| [ret as _, 0]),
            (libc::SYS_fstat, [fd, statbuf, ..]) => {
                let statbuf = self.platform().validate_mut(statbuf)?;
                self.fstat(fd as _, statbuf).map(|_| [0, 0])
            }
            (libc::SYS_getegid, ..) => self.getegid().map(|ret| [ret as _, 0]),
            (libc::SYS_geteuid, ..) => self.geteuid().map(|ret| [ret as _, 0]),
            (libc::SYS_getgid, ..) => self.getgid().map(|ret| [ret as _, 0]),
            (libc::SYS_getpid, ..) => self.getpid().map(|ret| [ret as _, 0]),
            (libc::SYS_getrandom, [buf, buflen, flags, ..]) => {
                let buf = self.platform().validate_slice_mut(buf, buflen)?;
                self.getrandom(buf, flags as _).map(|ret| [ret as _, 0])
            }
            (libc::SYS_getuid, ..) => self.getuid().map(|ret| [ret as _, 0]),
            (libc::SYS_read, [fd, buf, count, ..]) => {
                let buf = self.platform().validate_slice_mut(buf, count)?;
                self.read(fd as _, buf).map(|ret| [ret, 0])
            }
            (libc::SYS_socket, [domain, typ, protocol, ..]) => self
                .socket(domain as _, typ as _, protocol as _)
                .map(|ret| [ret as _, 0]),
            (libc::SYS_sync, ..) => self.sync().map(|_| [0, 0]),
            (libc::SYS_uname, [buf, ..]) => {
                let buf = self.platform().validate_mut(buf)?;
                self.uname(buf).map(|_| [0, 0])
            }
            (libc::SYS_write, [fd, buf, count, ..]) => {
                let buf = self.platform().validate_slice(buf, count)?;
                self.write(fd as _, buf).map(|ret| [ret, 0])
            }
            _ => Err(ENOSYS),
        }
    }

    /// Executes [`close`](https://man7.org/linux/man-pages/man2/close.2.html) syscall akin to [`libc::close`].
    fn close(&mut self, fd: c_int) -> Result<()> {
        self.execute(syscall::Close { fd })?
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

    /// Executes [`getuid`](https://man7.org/linux/man-pages/man2/getuid.2.html) syscall akin to [`libc::getuid`].
    fn getuid(&mut self) -> Result<uid_t> {
        self.execute(syscall::Getuid)
    }

    /// Executes [`exit`](https://man7.org/linux/man-pages/man2/exit.2.html) syscall akin to [`libc::exit`].
    fn exit(&mut self, status: c_int) -> Result<()> {
        self.execute(syscall::Exit { status })??;
        self.attacked()
    }

    /// Executes [`exit_group`](https://man7.org/linux/man-pages/man2/exit_group.2.html) syscall akin to [`libc::exit_group`].
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

    /// Executes [`read`](https://man7.org/linux/man-pages/man2/read.2.html) syscall akin to [`libc::read`].
    fn read(&mut self, fd: c_int, buf: &mut [u8]) -> Result<size_t> {
        self.execute(syscall::Read { fd, buf })?
            .unwrap_or_else(|| self.attacked())
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
    type Platform = P;
    type Allocator = Alloc<'a, phase::Stage>;

    fn platform(&mut self) -> &mut Self::Platform {
        &mut self.platform
    }

    fn allocator(&mut self) -> Self::Allocator {
        self.alloc.stage()
    }
}
