// SPDX-License-Identifier: Apache-2.0

use super::alloc::{phase, Alloc, Allocator, Collect, Commit, Committer};
use super::syscall::types::{SockaddrInput, SockaddrOutput, SockoptInput};
use super::{syscall, Call, Platform, ThreadLocalStorage, SIGRTMAX};
use crate::{item, Result};
use core::ptr::NonNull;

use libc::{
    c_int, c_uint, c_ulong, c_void, clockid_t, epoll_event, gid_t, off_t, pid_t, sigaction,
    sigset_t, size_t, stack_t, stat, timespec, uid_t, utsname, EFAULT, ENOSYS,
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

    /// Executes [`accept`](https://man7.org/linux/man-pages/man2/accept.2.html) syscall akin to [`libc::accept`].
    fn accept<'a>(
        &mut self,
        sockfd: c_int,
        addr: Option<impl Into<SockaddrOutput<'a>>>,
    ) -> Result<c_int> {
        self.execute(syscall::Accept { sockfd, addr })?
    }

    /// Executes [`accept4`](https://man7.org/linux/man-pages/man2/accept4.2.html) syscall akin to [`libc::accept4`].
    fn accept4<'a>(
        &mut self,
        sockfd: c_int,
        addr: Option<impl Into<SockaddrOutput<'a>>>,
        flags: c_int,
    ) -> Result<c_int> {
        self.execute(syscall::Accept4 {
            sockfd,
            addr,
            flags,
        })?
    }

    /// Executes [`arch_prctl`](https://man7.org/linux/man-pages/man2/arch_prctl.2.html).
    fn arch_prctl(&mut self, code: c_int, addr: c_ulong) -> Result<()>;

    /// Executes [`bind`](https://man7.org/linux/man-pages/man2/bind.2.html) syscall akin to [`libc::bind`].
    fn bind<'a>(&mut self, sockfd: c_int, addr: impl Into<SockaddrInput<'a>>) -> Result<()> {
        self.execute(syscall::Bind { sockfd, addr })?
    }

    /// Executes [`clock_gettime`](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) syscall akin to [`libc::clock_gettime`].
    fn clock_gettime(&mut self, clockid: clockid_t, tp: &mut timespec) -> Result<()> {
        self.execute(syscall::ClockGettime { clockid, tp })?
    }

    /// Executes [`brk`](https://man7.org/linux/man-pages/man2/brk.2.html) syscall akin to [`libc::brk`].
    fn brk(&mut self, addr: NonNull<c_void>) -> Result<()>;

    /// Executes [`close`](https://man7.org/linux/man-pages/man2/close.2.html) syscall akin to [`libc::close`].
    fn close(&mut self, fd: c_int) -> Result<()> {
        self.execute(syscall::Close { fd })?
    }

    /// Executes [`connect`](https://man7.org/linux/man-pages/man2/connect.2.html) syscall akin to [`libc::connect`].
    fn connect<'a>(&mut self, sockfd: c_int, addr: impl Into<SockaddrInput<'a>>) -> Result<()> {
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

    /// Executes [`epoll_create1`](https://man7.org/linux/man-pages/man2/epoll_create1.2.html) syscall akin to [`libc::epoll_create1`].
    fn epoll_create1(&mut self, flags: c_int) -> Result<c_int> {
        self.execute(syscall::EpollCreate1 { flags })?
    }

    /// Executes [`epoll_ctl`](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html) syscall akin to [`libc::epoll_ctl`].
    fn epoll_ctl(&mut self, epfd: c_int, op: c_int, fd: c_int, event: &epoll_event) -> Result<()> {
        self.execute(syscall::EpollCtl {
            epfd,
            op,
            fd,
            event,
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
    fn getsockname<'a>(
        &mut self,
        sockfd: c_int,
        addr: impl Into<SockaddrOutput<'a>>,
    ) -> Result<()> {
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

    /// Executes [`madvise`](https://man7.org/linux/man-pages/man2/madvise.2.html) syscall akin to [`libc::madvise`].
    fn madvise(&mut self, addr: NonNull<c_void>, length: size_t, advice: c_int) -> Result<()>;

    /// Executes [`mmap`](https://man7.org/linux/man-pages/man2/mmap.2.html) syscall akin to [`libc::mmap`].
    fn mmap(
        &mut self,
        addr: Option<NonNull<c_void>>,
        length: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> Result<NonNull<c_void>>;

    /// Executes [`mprotect`](https://man7.org/linux/man-pages/man2/mprotect.2.html) syscall akin to [`libc::mprotect`].
    fn mprotect(&mut self, addr: NonNull<c_void>, len: size_t, prot: c_int) -> Result<()>;

    /// Executes [`munmap`](https://man7.org/linux/man-pages/man2/munmap.2.html) syscall akin to [`libc::munmap`].
    fn munmap(&mut self, addr: NonNull<c_void>, length: size_t) -> Result<()>;

    /// Executes [`read`](https://man7.org/linux/man-pages/man2/read.2.html) syscall akin to [`libc::read`].
    fn read(&mut self, fd: c_int, buf: &mut [u8]) -> Result<size_t> {
        self.execute(syscall::Read { fd, buf })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`readlink`](https://man7.org/linux/man-pages/man2/readlink.2.html) syscall akin to [`libc::readlink`].
    fn readlink(&mut self, pathname: &[u8], buf: &mut [u8]) -> Result<size_t> {
        self.execute(syscall::Readlink { pathname, buf })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`recv`](https://man7.org/linux/man-pages/man2/recv.2.html) syscall akin to [`libc::recv`].
    fn recv(&mut self, sockfd: c_int, buf: &mut [u8], flags: c_int) -> Result<size_t> {
        self.execute(syscall::Recv { sockfd, buf, flags })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`recvfrom`](https://man7.org/linux/man-pages/man2/recvfrom.2.html) syscall akin to [`libc::recvfrom`].
    fn recvfrom(
        &mut self,
        sockfd: c_int,
        buf: &mut [u8],
        flags: c_int,
        src_addr: SockaddrOutput,
    ) -> Result<size_t> {
        self.execute(syscall::Recvfrom {
            sockfd,
            buf,
            flags,
            src_addr,
        })?
        .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`rt_sigaction`](https://man7.org/linux/man-pages/man2/rt_sigaction.2.html).
    fn rt_sigaction(
        &mut self,
        signum: c_int,
        act: Option<&sigaction>,
        oldact: Option<&mut Option<sigaction>>,
        sigsetsize: size_t,
    ) -> Result<()>;

    /// Executes [`rt_sigprocmask`](https://man7.org/linux/man-pages/man2/rt_sigprocmask.2.html).
    fn rt_sigprocmask(
        &mut self,
        how: c_int,
        set: Option<&sigset_t>,
        oldset: Option<&mut sigset_t>,
        sigsetsize: size_t,
    ) -> Result<()> {
        self.execute(syscall::RtSigprocmask {
            how,
            set,
            oldset,
            sigsetsize,
        })?
    }

    /// Executes [`sigaltstack`](https://man7.org/linux/man-pages/man2/sigaltstack.2.html) syscall akin to [`libc::sigaltstack`].
    fn sigaltstack(&mut self, ss: &stack_t, old_ss: Option<&mut stack_t>) -> Result<()> {
        self.execute(syscall::Sigaltstack { ss, old_ss })?
    }

    /// Executes [`setsockopt`](https://man7.org/linux/man-pages/man2/setsockopt.2.html) syscall akin to [`libc::setsockopt`].
    fn setsockopt<'a>(
        &mut self,
        sockfd: c_int,
        level: c_int,
        optname: c_int,
        optval: Option<impl Into<SockoptInput<'a>>>,
    ) -> Result<c_int> {
        self.execute(syscall::Setsockopt {
            sockfd,
            level,
            optname,
            optval,
        })?
    }

    /// Executes [`set_tid_address`](https://man7.org/linux/man-pages/man2/set_tid_address.2.html).
    fn set_tid_address(&mut self, tidptr: &mut c_int) -> Result<pid_t> {
        self.execute(syscall::SetTidAddress { tidptr })
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
    tls: &'a mut ThreadLocalStorage,
}

impl<'a, P: Platform> Handler<'a, P> {
    /// Creates a new [`Handler`] given a mutable borrow of the sallyport block,
    /// [`Platform`] and [`ThreadLocalStorage`].
    pub fn new(block: &'a mut [usize], platform: P, tls: &'a mut ThreadLocalStorage) -> Self {
        Self {
            alloc: Alloc::new(block),
            platform,
            tls,
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
            (libc::SYS_accept, [sockfd, addr, addrlen, ..]) => {
                let addr = if addr == 0 {
                    None
                } else {
                    self.platform
                        .validate_sockaddr_output(addr, addrlen)
                        .map(Some)?
                };
                self.accept(sockfd as _, addr).map(|ret| [ret as _, 0])
            }
            (libc::SYS_accept4, [sockfd, addr, addrlen, flags, ..]) => {
                let addr = if addr == 0 {
                    None
                } else {
                    self.platform
                        .validate_sockaddr_output(addr, addrlen)
                        .map(Some)?
                };
                self.accept4(sockfd as _, addr, flags as _)
                    .map(|ret| [ret as _, 0])
            }
            (libc::SYS_arch_prctl, [code, addr, ..]) => {
                self.arch_prctl(code as _, addr as _).map(|_| [0, 0])
            }
            (libc::SYS_bind, [sockfd, addr, addrlen, ..]) => {
                let addr = self.platform.validate_slice(addr, addrlen)?;
                self.bind(sockfd as _, addr).map(|_| [0, 0])
            }
            (libc::SYS_brk, [addr, ..]) => {
                let addr = NonNull::new(addr as _).ok_or(EFAULT)?;
                self.brk(addr).map(|_| [0, 0])
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
            (libc::SYS_epoll_create1, [flags, ..]) => {
                self.epoll_create1(flags as _).map(|ret| [ret as _, 0])
            }
            (libc::SYS_epoll_ctl, [epfd, op, fd, event, ..]) => {
                let event = self.platform.validate(event)?;
                self.epoll_ctl(epfd as _, op as _, fd as _, event)
                    .map(|_| [0, 0])
            }
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
                let addr = self.platform.validate_sockaddr_output(addr, addrlen)?;
                self.getsockname(sockfd as _, addr).map(|_| [0, 0])
            }
            (libc::SYS_getuid, ..) => self.getuid().map(|ret| [ret as _, 0]),
            (libc::SYS_listen, [sockfd, backlog, ..]) => {
                self.listen(sockfd as _, backlog as _).map(|_| [0, 0])
            }
            (libc::SYS_madvise, [addr, length, advice, ..]) => {
                let addr = NonNull::new(addr as _).ok_or(EFAULT)?;
                self.madvise(addr, length, advice as _).map(|_| [0, 0])
            }
            (libc::SYS_mmap, [addr, length, prot, flags, fd, offset, ..]) => self
                .mmap(
                    NonNull::new(addr as _),
                    length,
                    prot as _,
                    flags as _,
                    fd as _,
                    offset as _,
                )
                .map(|ret| [ret.as_ptr() as _, 0]),
            (libc::SYS_mprotect, [addr, len, prot, ..]) => {
                let addr = NonNull::new(addr as _).ok_or(EFAULT)?;
                self.mprotect(addr, len, prot as _).map(|_| [0, 0])
            }
            (libc::SYS_munmap, [addr, length, ..]) => {
                let addr = NonNull::new(addr as _).ok_or(EFAULT)?;
                self.munmap(addr, length).map(|_| [0, 0])
            }
            (libc::SYS_read, [fd, buf, count, ..]) => {
                let buf = self.platform.validate_slice_mut(buf, count)?;
                self.read(fd as _, buf).map(|ret| [ret, 0])
            }
            (libc::SYS_readlink, [pathname, buf, bufsiz, ..]) => {
                let pathname = self.platform.validate_str(pathname)?;
                let buf = self.platform.validate_slice_mut(buf, bufsiz)?;
                self.readlink(pathname, buf).map(|ret| [ret, 0])
            }
            (libc::SYS_recvfrom, [sockfd, buf, len, flags, src_addr, addrlen, ..]) => {
                let buf = self.platform.validate_slice_mut(buf, len)?;
                if src_addr == 0 {
                    self.recv(sockfd as _, buf, flags as _)
                } else {
                    let src_addr = self.platform.validate_sockaddr_output(src_addr, addrlen)?;
                    self.recvfrom(sockfd as _, buf, flags as _, src_addr)
                }
                .map(|ret| [ret, 0])
            }
            (libc::SYS_rt_sigaction, [signum, act, oldact, sigsetsize, ..]) => {
                let act = if act == 0 {
                    None
                } else {
                    self.platform.validate(act).map(Some)?
                };
                let oldact = if oldact == 0 {
                    None
                } else {
                    self.platform.validate_mut(oldact).map(Some)?
                };
                self.rt_sigaction(signum as _, act, oldact, sigsetsize as _)
                    .map(|_| [0, 0])
            }
            (libc::SYS_rt_sigprocmask, [how, set, oldset, sigsetsize, ..]) => {
                let set = if set == 0 {
                    None
                } else {
                    self.platform.validate(set).map(Some)?
                };
                let oldset = if oldset == 0 {
                    None
                } else {
                    self.platform.validate_mut(oldset).map(Some)?
                };
                self.rt_sigprocmask(how as _, set, oldset, sigsetsize as _)
                    .map(|_| [0, 0])
            }
            (libc::SYS_setsockopt, [sockfd, level, optname, optval, optlen, ..]) => {
                let optval = if optval == 0 {
                    None
                } else {
                    self.platform
                        .validate_slice::<u8>(optval, optlen)
                        .map(Some)?
                };
                self.setsockopt(sockfd as _, level as _, optname as _, optval)
                    .map(|ret| [ret as _, 0])
            }
            (libc::SYS_set_tid_address, [tidptr, ..]) => {
                let tidptr = self.platform.validate_mut(tidptr)?;
                self.set_tid_address(tidptr).map(|ret| [ret as _, 0])
            }
            (libc::SYS_sigaltstack, [ss, old_ss, ..]) => {
                let ss = self.platform.validate(ss)?;
                let old_ss = if old_ss == 0 {
                    None
                } else {
                    self.platform.validate_mut(old_ss).map(Some)?
                };
                self.sigaltstack(ss, old_ss).map(|_| [0, 0])
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

    fn arch_prctl(&mut self, _: c_int, _: c_ulong) -> Result<()> {
        Err(ENOSYS)
    }

    fn brk(&mut self, _: NonNull<c_void>) -> Result<()> {
        Err(ENOSYS)
    }

    fn madvise(&mut self, _: NonNull<c_void>, _: size_t, _: c_int) -> Result<()> {
        Err(ENOSYS)
    }

    fn mmap(
        &mut self,
        _: Option<NonNull<c_void>>,
        _: size_t,
        _: c_int,
        _: c_int,
        _: c_int,
        _: off_t,
    ) -> Result<NonNull<c_void>> {
        Err(ENOSYS)
    }

    fn mprotect(&mut self, _: NonNull<c_void>, _: size_t, _: c_int) -> Result<()> {
        Err(ENOSYS)
    }

    fn munmap(&mut self, _: NonNull<c_void>, _: size_t) -> Result<()> {
        Err(ENOSYS)
    }

    #[inline]
    fn rt_sigaction(
        &mut self,
        signum: c_int,
        act: Option<&sigaction>,
        oldact: Option<&mut Option<sigaction>>,
        sigsetsize: size_t,
    ) -> Result<()> {
        if signum >= SIGRTMAX || sigsetsize != 8 {
            return Err(libc::EINVAL);
        }
        if let Some(oldact) = oldact {
            *oldact = self.tls.actions[signum as usize];
        }
        if let Some(act) = act {
            self.tls.actions[signum as usize] = Some(*act);
        }
        Ok(())
    }
}
