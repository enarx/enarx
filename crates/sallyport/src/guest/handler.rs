// SPDX-License-Identifier: Apache-2.0

use super::alloc::{Alloc, Allocator, Collect, Commit, Committer};
use super::call::kind;
use super::syscall::types::{SockaddrInput, SockaddrOutput, SockoptInput};
use super::{enarxcall, gdbcall, syscall, Call, Platform, ThreadLocalStorage, SIGRTMAX};
use crate::item::enarxcall::sgx;
use crate::item::syscall::sigaction;
use crate::{item, Result};
use core::arch::x86_64::CpuidResult;
use core::mem::size_of;
use core::ptr::NonNull;
use core::slice;

use libc::{
    c_int, c_uint, c_ulong, c_void, clockid_t, epoll_event, gid_t, mode_t, off_t, pid_t, pollfd,
    sigset_t, size_t, stack_t, stat, timespec, uid_t, utsname, Ioctl, EBADFD, EFAULT, EINVAL,
    ENOSYS, ENOTSUP, ENOTTY, FIONBIO, FIONREAD, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO,
    TIOCGWINSZ,
};

/// Guest request handler.
pub trait Handler {
    /// Suspend guest execution and pass control to host.
    /// This function will return when the host passes control back to the guest.
    fn sally(&mut self) -> Result<()>;

    /// Returns an immutable borrow of the sallyport block.
    fn block(&self) -> &[usize];

    /// Returns a mutable borrow of the sallyport block.
    fn block_mut(&mut self) -> &mut [usize];

    /// Returns a mutable borrow of shared [ThreadLocalStorage].
    fn thread_local_storage(&mut self) -> &mut ThreadLocalStorage;

    /// Executes an arbitrary call.
    /// Examples of calls that this method can execute are:
    /// - [`syscall::Exit`]
    /// - [`syscall::Read`]
    /// - [`syscall::Write`]
    /// - [`gdbcall::Read`]
    /// - [`gdbcall::Write`]
    #[inline]
    fn execute<'a, K: kind::Kind, T: Call<'a, K>>(&mut self, call: T) -> Result<T::Collected> {
        let mut alloc = Alloc::new(self.block_mut()).stage();
        let ((call, len), mut end_ref) =
            alloc.reserve_input(|alloc| alloc.section(|alloc| call.stage(alloc)))?;

        let alloc = alloc.commit();
        let call = call.commit(&alloc);
        let alloc = if len > 0 {
            end_ref.copy_from(
                &alloc,
                item::Header {
                    kind: item::Kind::End,
                    size: 0,
                },
            );
            let collect = alloc.sally();
            self.sally()?;
            collect(self.block())?
        } else {
            alloc.collect()
        };
        Ok(call.collect(&alloc))
    }

    /// Loops infinitely trying to exit.
    #[inline]
    fn attacked(&mut self) -> ! {
        loop {
            let _ = self.exit(1);
        }
    }

    // Syscalls, sorted alphabetically.

    /// Executes [`accept`](https://man7.org/linux/man-pages/man2/accept.2.html) syscall akin to [`libc::accept`].
    #[inline]
    fn accept<'a>(
        &mut self,
        sockfd: c_int,
        addr: Option<impl Into<SockaddrOutput<'a>>>,
    ) -> Result<c_int> {
        self.execute(syscall::Accept { sockfd, addr })?
    }

    /// Executes [`accept4`](https://man7.org/linux/man-pages/man2/accept4.2.html) syscall akin to [`libc::accept4`].
    #[inline]
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
    fn arch_prctl(&mut self, platform: &impl Platform, code: c_int, addr: c_ulong) -> Result<()>;

    /// Executes [`bind`](https://man7.org/linux/man-pages/man2/bind.2.html) syscall akin to [`libc::bind`].
    #[inline]
    fn bind<'a>(&mut self, sockfd: c_int, addr: impl Into<SockaddrInput<'a>>) -> Result<()> {
        self.execute(syscall::Bind { sockfd, addr })?
    }

    /// Executes [`clock_gettime`](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) syscall akin to [`libc::clock_gettime`].
    #[inline]
    fn clock_gettime(&mut self, clockid: clockid_t, tp: &mut timespec) -> Result<()> {
        self.execute(syscall::ClockGettime { clockid, tp })?
    }

    /// Executes [`brk`](https://man7.org/linux/man-pages/man2/brk.2.html) syscall akin to [`libc::brk`].
    fn brk(
        &mut self,
        platform: &impl Platform,
        addr: Option<NonNull<c_void>>,
    ) -> Result<NonNull<c_void>>;

    /// Executes [`close`](https://man7.org/linux/man-pages/man2/close.2.html) syscall akin to [`libc::close`].
    #[inline]
    fn close(&mut self, fd: c_int) -> Result<()> {
        self.execute(syscall::Close { fd })?
    }

    /// Executes [`connect`](https://man7.org/linux/man-pages/man2/connect.2.html) syscall akin to [`libc::connect`].
    #[inline]
    fn connect<'a>(&mut self, sockfd: c_int, addr: impl Into<SockaddrInput<'a>>) -> Result<()> {
        self.execute(syscall::Connect { sockfd, addr })?
    }

    /// Executes [`dup`](https://man7.org/linux/man-pages/man2/dup.2.html) syscall akin to [`libc::dup`].
    #[inline]
    fn dup(&mut self, oldfd: c_int) -> Result<()> {
        self.execute(syscall::Dup { oldfd })?
    }

    /// Executes [`dup2`](https://man7.org/linux/man-pages/man2/dup2.2.html) syscall akin to [`libc::dup2`].
    #[inline]
    fn dup2(&mut self, oldfd: c_int, newfd: c_int) -> Result<()> {
        self.execute(syscall::Dup2 { oldfd, newfd })?
    }

    /// Executes [`dup3`](https://man7.org/linux/man-pages/man2/dup3.2.html) syscall akin to [`libc::dup3`].
    #[inline]
    fn dup3(&mut self, oldfd: c_int, newfd: c_int, flags: c_int) -> Result<()> {
        self.execute(syscall::Dup3 {
            oldfd,
            newfd,
            flags,
        })?
    }

    /// Executes [`epoll_create1`](https://man7.org/linux/man-pages/man2/epoll_create1.2.html) syscall akin to [`libc::epoll_create1`].
    #[inline]
    fn epoll_create1(&mut self, flags: c_int) -> Result<c_int> {
        self.execute(syscall::EpollCreate1 { flags })?
    }

    /// Executes [`epoll_ctl`](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html) syscall akin to [`libc::epoll_ctl`].
    #[inline]
    fn epoll_ctl(&mut self, epfd: c_int, op: c_int, fd: c_int, event: &epoll_event) -> Result<()> {
        self.execute(syscall::EpollCtl {
            epfd,
            op,
            fd,
            event,
        })?
    }

    /// Executes [`epoll_wait`](https://man7.org/linux/man-pages/man2/epoll_wait.2.html) syscall akin to [`libc::epoll_wait`].
    #[inline]
    fn epoll_wait(
        &mut self,
        epfd: c_int,
        events: &mut [epoll_event],
        timeout: c_int,
    ) -> Result<c_int> {
        self.execute(syscall::EpollWait {
            epfd,
            events,
            timeout,
        })?
        .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`epoll_pwait`](https://man7.org/linux/man-pages/man2/epoll_pwait.2.html) syscall akin to [`libc::epoll_pwait`].
    #[inline]
    fn epoll_pwait(
        &mut self,
        epfd: c_int,
        events: &mut [epoll_event],
        timeout: c_int,
        sigmask: &sigset_t,
    ) -> Result<c_int> {
        self.execute(syscall::EpollPwait {
            epfd,
            events,
            timeout,
            sigmask,
        })?
        .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`eventfd2`](https://man7.org/linux/man-pages/man2/eventfd2.2.html).
    #[inline]
    fn eventfd2(&mut self, initval: c_int, flags: c_int) -> Result<c_int> {
        self.execute(syscall::Eventfd2 { initval, flags })?
    }

    /// Executes [`exit`](https://man7.org/linux/man-pages/man2/exit.2.html) syscall akin to [`libc::exit`].
    #[inline]
    fn exit(&mut self, status: c_int) -> Result<()> {
        self.execute(syscall::Exit { status })??;
        self.attacked()
    }

    /// Executes [`exit_group`](https://man7.org/linux/man-pages/man2/exit_group.2.html).
    #[inline]
    fn exit_group(&mut self, status: c_int) -> Result<()> {
        self.execute(syscall::ExitGroup { status })??;
        self.attacked()
    }

    /// Executes [`fcntl`](https://man7.org/linux/man-pages/man2/fcntl.2.html) syscall akin to [`libc::fcntl`].
    #[inline]
    fn fcntl(&mut self, fd: c_int, cmd: c_int, arg: c_int) -> Result<c_int> {
        self.execute(syscall::Fcntl { fd, cmd, arg })?
    }

    /// Executes [`fstat`](https://man7.org/linux/man-pages/man2/fstat.2.html) syscall akin to [`libc::fstat`].
    #[inline]
    fn fstat(&mut self, fd: c_int, statbuf: &mut stat) -> Result<()> {
        self.execute(syscall::Fstat { fd, statbuf })?
    }

    /// Executes [`getegid`](https://man7.org/linux/man-pages/man2/getegid.2.html) syscall akin to [`libc::getegid`].
    #[inline]
    fn getegid(&mut self) -> Result<gid_t> {
        self.execute(syscall::Getegid)
    }

    /// Executes [`geteuid`](https://man7.org/linux/man-pages/man2/geteuid.2.html) syscall akin to [`libc::geteuid`].
    #[inline]
    fn geteuid(&mut self) -> Result<uid_t> {
        self.execute(syscall::Geteuid)
    }

    /// Executes [`getgid`](https://man7.org/linux/man-pages/man2/getgid.2.html) syscall akin to [`libc::getgid`].
    #[inline]
    fn getgid(&mut self) -> Result<gid_t> {
        self.execute(syscall::Getgid)
    }

    /// Executes [`getpid`](https://man7.org/linux/man-pages/man2/getpid.2.html) syscall akin to [`libc::getpid`].
    #[inline]
    fn getpid(&mut self) -> Result<pid_t> {
        self.execute(syscall::Getpid)
    }

    /// Executes [`getrandom`](https://man7.org/linux/man-pages/man2/getrandom.2.html) syscall akin to [`libc::getrandom`].
    #[inline]
    fn getrandom(&mut self, buf: &mut [u8], flags: c_uint) -> Result<size_t> {
        self.execute(syscall::Getrandom { buf, flags })?
    }

    /// Executes [`getsockname`](https://man7.org/linux/man-pages/man2/getsockname.2.html) syscall akin to [`libc::getsockname`].
    #[inline]
    fn getsockname<'a>(
        &mut self,
        sockfd: c_int,
        addr: impl Into<SockaddrOutput<'a>>,
    ) -> Result<()> {
        self.execute(syscall::Getsockname { sockfd, addr })?
    }

    /// Executes [`getuid`](https://man7.org/linux/man-pages/man2/getuid.2.html) syscall akin to [`libc::getuid`].
    #[inline]
    fn getuid(&mut self) -> Result<uid_t> {
        self.execute(syscall::Getuid)
    }

    /// Executes [`ioctl`](https://man7.org/linux/man-pages/man2/ioctl.2.html) syscall akin to [`libc::ioctl`].
    #[inline]
    fn ioctl(&mut self, fd: c_int, request: Ioctl, argp: Option<&mut [u8]>) -> Result<c_int> {
        match (fd, request) {
            (STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO, TIOCGWINSZ) => {
                // the keep has no tty
                Err(ENOTTY)
            }
            (STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO, _) => Err(EINVAL),
            (_, FIONBIO | FIONREAD) => self.execute(syscall::Ioctl { fd, request, argp })?,
            _ => Err(EBADFD),
        }
    }

    /// Executes [`listen`](https://man7.org/linux/man-pages/man2/listen.2.html) syscall akin to [`libc::listen`].
    #[inline]
    fn listen(&mut self, sockfd: c_int, backlog: c_int) -> Result<()> {
        self.execute(syscall::Listen { sockfd, backlog })?
    }

    /// Executes [`madvise`](https://man7.org/linux/man-pages/man2/madvise.2.html) syscall akin to [`libc::madvise`].
    fn madvise(
        &mut self,
        platform: &impl Platform,
        addr: NonNull<c_void>,
        length: size_t,
        advice: c_int,
    ) -> Result<()>;

    /// Executes [`mmap`](https://man7.org/linux/man-pages/man2/mmap.2.html) syscall akin to [`libc::mmap`].
    #[allow(clippy::too_many_arguments)]
    fn mmap(
        &mut self,
        platform: &impl Platform,
        addr: Option<NonNull<c_void>>,
        length: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> Result<NonNull<c_void>>;

    /// Executes [`mprotect`](https://man7.org/linux/man-pages/man2/mprotect.2.html) syscall akin to [`libc::mprotect`].
    fn mprotect(
        &mut self,
        platform: &impl Platform,
        addr: NonNull<c_void>,
        len: size_t,
        prot: c_int,
    ) -> Result<()>;

    /// Executes [`munmap`](https://man7.org/linux/man-pages/man2/munmap.2.html) syscall akin to [`libc::munmap`].
    fn munmap(
        &mut self,
        platform: &impl Platform,
        addr: NonNull<c_void>,
        length: size_t,
    ) -> Result<()>;

    /// Executes [`nanosleep`](https://man7.org/linux/man-pages/man2/nanosleep.2.html) syscall akin to [`libc::nanosleep`].
    fn nanosleep(&mut self, req: &timespec, rem: Option<&mut timespec>) -> Result<()> {
        self.execute(syscall::Nanosleep { req, rem })?
    }

    /// Executes [`open`](https://man7.org/linux/man-pages/man2/open.2.html) syscall akin to [`libc::open`].
    ///
    /// `pathname` argument must contain the trailing nul terminator byte.
    fn open(&mut self, pathname: &[u8], flags: c_int, mode: Option<mode_t>) -> Result<c_int> {
        self.execute(syscall::Open {
            pathname,
            flags,
            mode,
        })?
    }

    /// Executes [`poll`](https://man7.org/linux/man-pages/man2/poll.2.html) syscall akin to [`libc::poll`].
    #[inline]
    fn poll(&mut self, fds: &mut [pollfd], timeout: c_int) -> Result<c_int> {
        self.execute(syscall::Poll { fds, timeout })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`read`](https://man7.org/linux/man-pages/man2/read.2.html) syscall akin to [`libc::read`].
    #[inline]
    fn read(&mut self, fd: c_int, buf: &mut [u8]) -> Result<size_t> {
        self.execute(syscall::Read { fd, buf })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`readlink`](https://man7.org/linux/man-pages/man2/readlink.2.html) syscall akin to [`libc::readlink`].
    ///
    /// `pathname` argument must contain the trailing nul terminator byte.
    #[inline]
    fn readlink(&mut self, pathname: &[u8], buf: &mut [u8]) -> Result<size_t> {
        self.execute(syscall::Readlink { pathname, buf })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`readv`](https://man7.org/linux/man-pages/man2/readv.2.html) syscall by mapping
    /// it onto a single [`read`](https://man7.org/linux/man-pages/man2/read.2.html).
    #[inline]
    fn readv<T: ?Sized, U, V>(&mut self, fd: c_int, iovs: &mut T) -> Result<size_t>
    where
        for<'a> &'a T: IntoIterator<Item = &'a U>,
        for<'a> &'a mut T: IntoIterator<Item = &'a mut V>,
        U: AsRef<[u8]>,
        V: AsMut<[u8]>,
    {
        self.execute(syscall::Readv { fd, iovs })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`recv`](https://man7.org/linux/man-pages/man2/recv.2.html) syscall akin to [`libc::recv`].
    #[inline]
    fn recv(&mut self, sockfd: c_int, buf: &mut [u8], flags: c_int) -> Result<size_t> {
        self.execute(syscall::Recv { sockfd, buf, flags })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`recvfrom`](https://man7.org/linux/man-pages/man2/recvfrom.2.html) syscall akin to [`libc::recvfrom`].
    #[inline]
    fn recvfrom<'a>(
        &mut self,
        sockfd: c_int,
        buf: &'a mut [u8],
        flags: c_int,
        src_addr: impl Into<SockaddrOutput<'a>>,
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
        let tls = self.thread_local_storage();
        if let Some(oldact) = oldact {
            *oldact = tls.actions[signum as usize];
        }
        if let Some(act) = act {
            tls.actions[signum as usize] = Some(*act);
        }
        Ok(())
    }

    /// Executes [`rt_sigprocmask`](https://man7.org/linux/man-pages/man2/rt_sigprocmask.2.html).
    #[inline]
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
    #[inline]
    fn sigaltstack(&mut self, ss: Option<&stack_t>, old_ss: Option<&mut stack_t>) -> Result<()> {
        self.execute(syscall::Sigaltstack { ss, old_ss })?
    }

    /// Executes [`send`](https://man7.org/linux/man-pages/man2/send.2.html) syscall akin to [`libc::send`].
    #[inline]
    fn send(&mut self, sockfd: c_int, buf: &[u8], flags: c_int) -> Result<size_t> {
        self.execute(syscall::Send { sockfd, buf, flags })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`sendto`](https://man7.org/linux/man-pages/man2/sendto.2.html) syscall akin to [`libc::sendto`].
    #[inline]
    fn sendto<'a>(
        &mut self,
        sockfd: c_int,
        buf: &'a [u8],
        flags: c_int,
        dest_addr: impl Into<SockaddrInput<'a>>,
    ) -> Result<size_t> {
        self.execute(syscall::Sendto {
            sockfd,
            buf,
            flags,
            dest_addr,
        })?
        .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`setsockopt`](https://man7.org/linux/man-pages/man2/setsockopt.2.html) syscall akin to [`libc::setsockopt`].
    #[inline]
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
    #[inline]
    fn set_tid_address(&mut self, tidptr: &mut c_int) -> Result<pid_t> {
        self.execute(syscall::SetTidAddress { tidptr })
    }

    /// Executes [`socket`](https://man7.org/linux/man-pages/man2/socket.2.html) syscall akin to [`libc::socket`].
    #[inline]
    fn socket(&mut self, domain: c_int, typ: c_int, protocol: c_int) -> Result<c_int> {
        self.execute(syscall::Socket {
            domain,
            typ,
            protocol,
        })?
    }

    /// Executes [`sync`](https://man7.org/linux/man-pages/man2/sync.2.html) syscall akin to [`libc::sync`].
    #[inline]
    fn sync(&mut self) -> Result<()> {
        self.execute(syscall::Sync)?
    }

    /// Executes [`uname`](https://man7.org/linux/man-pages/man2/uname.2.html) syscall akin to [`libc::uname`].
    #[inline]
    fn uname(&mut self, buf: &mut utsname) -> Result<()> {
        self.execute(syscall::Uname { buf })?
    }

    /// Executes [`write`](https://man7.org/linux/man-pages/man2/write.2.html) syscall akin to [`libc::write`].
    #[inline]
    fn write(&mut self, fd: c_int, buf: &[u8]) -> Result<size_t> {
        self.execute(syscall::Write { fd, buf })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes [`writev`](https://man7.org/linux/man-pages/man2/writev.2.html) syscall by mapping
    /// it onto a single [`write`](https://man7.org/linux/man-pages/man2/write.2.html).
    #[inline]
    fn writev<T: ?Sized, U>(&mut self, fd: c_int, iovs: &T) -> Result<size_t>
    where
        for<'a> &'a T: IntoIterator<Item = &'a U>,
        U: AsRef<[u8]>,
    {
        self.execute(syscall::Writev { fd, iovs })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Executes a supported syscall expressed as an opaque 7-word array akin to [`libc::syscall`].
    ///
    /// # Safety
    ///
    /// This method is unsafe, because it allows execution of arbitrary syscalls on the host, which is
    /// intrinsically unsafe.
    ///
    /// It can also produce multiple references to the same memory.
    #[inline]
    unsafe fn syscall(
        &mut self,
        platform: &impl Platform,
        registers: [usize; 7],
    ) -> Result<[usize; 2]> {
        let [num, argv @ ..] = registers;
        match (num as _, argv) {
            (libc::SYS_accept, [sockfd, addr, addrlen, ..]) => {
                let addr = if addr == 0 {
                    None
                } else {
                    platform.validate_sockaddr_output(addr, addrlen).map(Some)?
                };
                self.accept(sockfd as _, addr).map(|ret| [ret as _, 0])
            }
            (libc::SYS_accept4, [sockfd, addr, addrlen, flags, ..]) => {
                let addr = if addr == 0 {
                    None
                } else {
                    platform.validate_sockaddr_output(addr, addrlen).map(Some)?
                };
                self.accept4(sockfd as _, addr, flags as _)
                    .map(|ret| [ret as _, 0])
            }
            (libc::SYS_arch_prctl, [code, addr, ..]) => self
                .arch_prctl(platform, code as _, addr as _)
                .map(|_| [0, 0]),
            (libc::SYS_bind, [sockfd, addr, addrlen, ..]) => {
                let addr = platform.validate_slice(addr, addrlen)?;
                self.bind(sockfd as _, addr).map(|_| [0, 0])
            }
            (libc::SYS_brk, [addr, ..]) => self
                .brk(platform, NonNull::new(addr as _))
                .map(|ret| [ret.as_ptr() as _, 0]),
            (libc::SYS_clock_gettime, [clockid, tp, ..]) => {
                let tp = platform.validate_mut(tp)?;
                self.clock_gettime(clockid as _, tp).map(|_| [0, 0])
            }
            (libc::SYS_close, [fd, ..]) => self.close(fd as _).map(|_| [0, 0]),
            (libc::SYS_connect, [sockfd, addr, addrlen, ..]) => {
                let addr = platform.validate_slice(addr, addrlen)?;
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
                let event = platform.validate(event)?;
                self.epoll_ctl(epfd as _, op as _, fd as _, event)
                    .map(|_| [0, 0])
            }
            (libc::SYS_epoll_pwait, [epfd, events, maxevents, timeout, sigmask, ..]) => {
                let events = platform.validate_slice_mut(events, maxevents)?;
                if sigmask == 0 {
                    self.epoll_wait(epfd as _, events, timeout as _)
                } else {
                    let sigmask = platform.validate(sigmask)?;
                    self.epoll_pwait(epfd as _, events, timeout as _, sigmask)
                }
                .map(|ret| [ret as _, 0])
            }
            (libc::SYS_epoll_wait, [epfd, events, maxevents, timeout, ..]) => {
                let events = platform.validate_slice_mut(events, maxevents)?;
                self.epoll_wait(epfd as _, events, timeout as _)
                    .map(|ret| [ret as _, 0])
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
                let statbuf = platform.validate_mut(statbuf)?;
                self.fstat(fd as _, statbuf).map(|_| [0, 0])
            }
            (libc::SYS_getegid, ..) => self.getegid().map(|ret| [ret as _, 0]),
            (libc::SYS_geteuid, ..) => self.geteuid().map(|ret| [ret as _, 0]),
            (libc::SYS_getgid, ..) => self.getgid().map(|ret| [ret as _, 0]),
            (libc::SYS_getpid, ..) => self.getpid().map(|ret| [ret as _, 0]),
            (libc::SYS_getrandom, [buf, buflen, flags, ..]) => {
                let buf = platform.validate_slice_mut(buf, buflen)?;
                self.getrandom(buf, flags as _).map(|ret| [ret as _, 0])
            }
            (libc::SYS_getsockname, [sockfd, addr, addrlen, ..]) => {
                let addr = platform.validate_sockaddr_output(addr, addrlen)?;
                self.getsockname(sockfd as _, addr).map(|_| [0, 0])
            }
            (libc::SYS_getuid, ..) => self.getuid().map(|ret| [ret as _, 0]),
            (libc::SYS_ioctl, [fd, request, argp, ..]) => {
                let argp = if argp == 0 {
                    None
                } else {
                    match request as _ {
                        FIONBIO | FIONREAD => platform.validate_mut::<c_int>(argp).map(|argp| {
                            Some(slice::from_raw_parts_mut(
                                argp as *mut _ as _,
                                size_of::<c_int>(),
                            ))
                        })?,
                        _ => return Err(ENOTSUP),
                    }
                };
                self.ioctl(fd as _, request as _, argp)
                    .map(|ret| [ret as _, 0])
            }
            (libc::SYS_listen, [sockfd, backlog, ..]) => {
                self.listen(sockfd as _, backlog as _).map(|_| [0, 0])
            }
            (libc::SYS_madvise, [addr, length, advice, ..]) => {
                let addr = NonNull::new(addr as _).ok_or(EFAULT)?;
                self.madvise(platform, addr, length, advice as _)
                    .map(|_| [0, 0])
            }
            (libc::SYS_mmap, [addr, length, prot, flags, fd, offset, ..]) => self
                .mmap(
                    platform,
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
                self.mprotect(platform, addr, len, prot as _)
                    .map(|_| [0, 0])
            }
            (libc::SYS_munmap, [addr, length, ..]) => {
                let addr = NonNull::new(addr as _).ok_or(EFAULT)?;
                self.munmap(platform, addr, length).map(|_| [0, 0])
            }
            (libc::SYS_nanosleep, [req, rem, ..]) => {
                let req = platform.validate(req)?;
                let rem = if rem == 0 {
                    None
                } else {
                    platform.validate_mut(rem).map(Some)?
                };
                self.nanosleep(req, rem).map(|_| [0, 0])
            }
            (libc::SYS_open, [pathname, flags, mode, ..]) => {
                let pathname = platform.validate_str(pathname)?;
                let mode = if mode == 0 { None } else { Some(mode as _) };
                self.open(pathname, flags as _, mode)
                    .map(|ret| [ret as _, 0])
            }
            (libc::SYS_poll, [fds, nfds, timeout, ..]) => {
                let fds = platform.validate_slice_mut(fds, nfds)?;
                self.poll(fds, timeout as _).map(|ret| [ret as _, 0])
            }
            (libc::SYS_read, [fd, buf, count, ..]) => {
                let buf = platform.validate_slice_mut(buf, count)?;
                self.read(fd as _, buf).map(|ret| [ret, 0])
            }
            (libc::SYS_readlink, [pathname, buf, bufsiz, ..]) => {
                let pathname = platform.validate_str(pathname)?;
                let buf = platform.validate_slice_mut(buf, bufsiz)?;
                self.readlink(pathname, buf).map(|ret| [ret, 0])
            }
            (libc::SYS_readv, [fd, iov, iovcnt, ..]) => {
                let iovs = platform.validate_iovec_slice_mut(iov, iovcnt)?;
                self.readv(fd as _, iovs).map(|ret| [ret, 0])
            }
            (libc::SYS_recvfrom, [sockfd, buf, len, flags, src_addr, addrlen, ..]) => {
                let buf = platform.validate_slice_mut(buf, len)?;
                if src_addr == 0 {
                    self.recv(sockfd as _, buf, flags as _)
                } else {
                    let src_addr = platform.validate_sockaddr_output(src_addr, addrlen)?;
                    self.recvfrom(sockfd as _, buf, flags as _, src_addr)
                }
                .map(|ret| [ret, 0])
            }
            (libc::SYS_rt_sigaction, [signum, act, oldact, sigsetsize, ..]) => {
                let act = if act == 0 {
                    None
                } else {
                    platform.validate(act).map(Some)?
                };
                let oldact = if oldact == 0 {
                    None
                } else {
                    platform.validate_mut(oldact).map(Some)?
                };
                self.rt_sigaction(signum as _, act, oldact, sigsetsize as _)
                    .map(|_| [0, 0])
            }
            (libc::SYS_rt_sigprocmask, [how, set, oldset, sigsetsize, ..]) => {
                let set = if set == 0 {
                    None
                } else {
                    platform.validate(set).map(Some)?
                };
                let oldset = if oldset == 0 {
                    None
                } else {
                    platform.validate_mut(oldset).map(Some)?
                };
                self.rt_sigprocmask(how as _, set, oldset, sigsetsize as _)
                    .map(|_| [0, 0])
            }
            (libc::SYS_sendto, [sockfd, buf, len, flags, dest_addr, addrlen]) => {
                let buf = platform.validate_slice(buf, len)?;
                if dest_addr == 0 {
                    self.send(sockfd as _, buf, flags as _)
                } else {
                    let dest_addr = platform.validate_slice(dest_addr, addrlen)?;
                    self.sendto(sockfd as _, buf, flags as _, dest_addr)
                }
                .map(|ret| [ret, 0])
            }
            (libc::SYS_setsockopt, [sockfd, level, optname, optval, optlen, ..]) => {
                let optval = if optval == 0 {
                    None
                } else {
                    platform.validate_slice::<u8>(optval, optlen).map(Some)?
                };
                self.setsockopt(sockfd as _, level as _, optname as _, optval)
                    .map(|ret| [ret as _, 0])
            }
            (libc::SYS_set_tid_address, [tidptr, ..]) => {
                let tidptr = platform.validate_mut(tidptr)?;
                self.set_tid_address(tidptr).map(|ret| [ret as _, 0])
            }
            (libc::SYS_sigaltstack, [ss, old_ss, ..]) => {
                let ss = if ss == 0 {
                    None
                } else {
                    platform.validate(ss).map(Some)?
                };
                let old_ss = if old_ss == 0 {
                    None
                } else {
                    platform.validate_mut(old_ss).map(Some)?
                };
                self.sigaltstack(ss, old_ss).map(|_| [0, 0])
            }
            (libc::SYS_socket, [domain, typ, protocol, ..]) => self
                .socket(domain as _, typ as _, protocol as _)
                .map(|ret| [ret as _, 0]),
            (libc::SYS_sync, ..) => self.sync().map(|_| [0, 0]),
            (libc::SYS_uname, [buf, ..]) => {
                let buf = platform.validate_mut(buf)?;
                self.uname(buf).map(|_| [0, 0])
            }
            (libc::SYS_write, [fd, buf, count, ..]) => {
                let buf = platform.validate_slice(buf, count)?;
                self.write(fd as _, buf).map(|ret| [ret, 0])
            }
            (libc::SYS_writev, [fd, iov, iovcnt, ..]) => {
                let iovs = platform.validate_iovec_slice(iov, iovcnt)?;
                self.writev(fd as _, iovs).map(|ret| [ret, 0])
            }
            _ => Err(ENOSYS),
        }
    }

    // GDB calls, sorted alphabetically.

    #[cfg_attr(feature = "doc", doc = "Executes [gdbstub::conn::Connection::flush]")]
    #[inline]
    fn gdb_flush(&mut self) -> Result<()> {
        self.execute(gdbcall::Flush)?
    }

    #[cfg_attr(
        feature = "doc",
        doc = "Executes [gdbstub::conn::Connection::on_session_start]"
    )]
    #[inline]
    fn gdb_on_session_start(&mut self) -> Result<()> {
        self.execute(gdbcall::OnSessionStart)?
    }

    #[cfg_attr(feature = "doc", doc = "Executes [gdbstub::conn::ConnectionExt::peek]")]
    #[inline]
    fn gdb_peek(&mut self) -> Result<Option<u8>> {
        self.execute(gdbcall::Peek)?
    }

    #[cfg_attr(feature = "doc", doc = "Executes [gdbstub::conn::ConnectionExt::read]")]
    #[inline]
    fn gdb_read(&mut self) -> Result<u8> {
        self.execute(gdbcall::Read)?
    }

    #[cfg_attr(feature = "doc", doc = "Executes [gdbstub::conn::Connection::write]")]
    #[inline]
    fn gdb_write(&mut self, byte: u8) -> Result<()> {
        self.execute(gdbcall::Write { byte })?
    }

    #[cfg_attr(
        feature = "doc",
        doc = "Executes [gdbstub::conn::Connection::write_all] and returns the amount of bytes written"
    )]
    #[inline]
    fn gdb_write_all(&mut self, buf: &[u8]) -> Result<usize> {
        self.execute(gdbcall::WriteAll { buf })?
            .unwrap_or_else(|| self.attacked())
    }

    // Enarx calls, sorted alphabetically.

    /// Request an additional memory region and return the virtual address of allocated region.
    ///
    /// # Arguments
    ///
    /// - `size_exponent`: Page size expressed as an exponent of 2
    /// - `pages`: Number of pages to allocate
    /// - `addr`: Guest physical address where the memory should be allocated
    #[inline]
    fn balloon_memory(
        &mut self,
        size_exponent: usize,
        pages: usize,
        addr: *mut c_void,
    ) -> Result<usize> {
        self.execute(enarxcall::BalloonMemory {
            size_exponent,
            pages,
            addr,
        })?
    }

    /// Execute `cpuid` instruction storing the result in `result`.
    #[inline]
    fn cpuid(&mut self, leaf: u32, sub_leaf: u32, result: &mut CpuidResult) -> Result<()> {
        self.execute(enarxcall::Cpuid {
            leaf,
            sub_leaf,
            result,
        })?
    }

    /// Requests SGX quote from the host given a report and returns the length of the quote on success.
    #[inline]
    fn get_sgx_quote(&mut self, report: &sgx::Report, quote: &mut [u8]) -> Result<usize> {
        self.execute(enarxcall::GetSgxQuote { report, quote })?
            .unwrap_or_else(|| self.attacked())
    }

    /// Requests [SGX `TargetInfo`](sgx::TargetInfo) from the host.
    #[inline]
    fn get_sgx_target_info(&mut self, info: &mut sgx::TargetInfo) -> Result<()> {
        self.execute(enarxcall::GetSgxTargetInfo { info })?
    }

    /// Gets number of memory slots available for ballooning from the host.
    ///
    /// KVM only has a limited number of memory ballooning slots, which varies by technology and kernel version.
    /// Knowing this number helps the shim allocator to decide how much memory to allocate for each slot.
    #[inline]
    fn mem_info(&mut self) -> Result<usize> {
        self.execute(enarxcall::MemInfo)?
    }
}
