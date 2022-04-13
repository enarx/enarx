// SPDX-License-Identifier: Apache-2.0

use super::{deref, deref_aligned};
use crate::libc::{
    self, epoll_event, pollfd, sigset_t, sockaddr_storage, socklen_t, timespec, EFAULT,
};
use crate::{item, Result, NULL};

use core::arch::asm;
use core::ffi::c_long;
use core::mem::align_of;
use core::ptr::{null, null_mut};

trait Execute {
    unsafe fn execute(self);
}

struct Syscall<'a, const ARGS: usize, const RETS: usize> {
    /// The syscall number for the request.
    ///
    /// See, for example, [`libc::SYS_exit`](libc::SYS_exit).
    num: c_long,

    /// The syscall argument vector.
    argv: [usize; ARGS],

    /// Return values.
    ret: [&'a mut usize; RETS],
}

impl Execute for Syscall<'_, 0, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 1, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 2, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 3, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 4, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        in("r10") self.argv[3],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 5, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        in("r10") self.argv[3],
        in("r8") self.argv[4],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

impl Execute for Syscall<'_, 6, 1> {
    #[inline]
    unsafe fn execute(self) {
        asm!(
        "syscall",
        inlateout("rax") self.num as usize => *self.ret[0],
        in("rdi") self.argv[0],
        in("rsi") self.argv[1],
        in("rdx") self.argv[2],
        in("r10") self.argv[3],
        in("r8") self.argv[4],
        in("r9") self.argv[5],
        lateout("rcx") _, // clobbered
        lateout("r11") _, // clobbered
        )
    }
}

/// Validates that `data` contains aligned sockaddr input at `addr_offset` of `addrlen` size
/// and returns an immutable pointer to address buffer on success.
#[inline]
fn deref_sockaddr_input(data: &mut [u8], addr_offset: usize, addrlen: usize) -> Result<*const u8> {
    let addr = unsafe { deref::<u8>(data, addr_offset, addrlen) }?;
    if addr.align_offset(align_of::<sockaddr_storage>()) != 0 {
        Err(EFAULT)
    } else {
        Ok(addr)
    }
}

/// Validates that `data` contains aligned sockaddr output at `addr_offset` and `addrlen_offset`
/// and returns mutable pointers to the address buffer and length on success.
#[inline]
fn deref_sockaddr_output(
    data: &mut [u8],
    addr_offset: usize,
    addrlen_offset: usize,
) -> Result<(*mut u8, *mut socklen_t)> {
    let addrlen = deref_aligned::<socklen_t>(data, addrlen_offset, 1)?;
    let addr = unsafe { deref::<u8>(data, addr_offset, *addrlen as _) }?;
    if addr.align_offset(align_of::<sockaddr_storage>()) != 0 {
        Err(EFAULT)
    } else {
        Ok((addr, addrlen))
    }
}

pub(super) unsafe fn execute(call: &mut item::Syscall, data: &mut [u8]) -> Result<()> {
    match call {
        item::Syscall {
            num,
            argv: [sockfd, addr_offset, addrlen_offset, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_accept as _ => {
            let (addr, addrlen) = if *addr_offset == NULL {
                (null_mut(), null_mut())
            } else {
                deref_sockaddr_output(data, *addr_offset, *addrlen_offset)?
            };
            Syscall {
                num: libc::SYS_accept,
                argv: [*sockfd, addr as _, addrlen as _],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [sockfd, addr_offset, addrlen_offset, flags, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_accept4 as _ => {
            let (addr, addrlen) = if *addr_offset == NULL {
                (null_mut(), null_mut())
            } else {
                deref_sockaddr_output(data, *addr_offset, *addrlen_offset)?
            };
            Syscall {
                num: libc::SYS_accept4,
                argv: [*sockfd, addr as _, addrlen as _, *flags],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [sockfd, addr_offset, addrlen, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_bind as _ => {
            let addr = deref_sockaddr_input(data, *addr_offset, *addrlen)?;
            Syscall {
                num: libc::SYS_bind,
                argv: [*sockfd, addr as _, *addrlen],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [clockid, res_offset, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_clock_getres as _ => {
            let res = if *res_offset == NULL {
                null_mut()
            } else {
                deref_aligned::<timespec>(data, *res_offset, 1)?
            };
            Syscall {
                num: libc::SYS_clock_getres,
                argv: [*clockid, res as _],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [clockid, tp_offset, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_clock_gettime as _ => {
            let tp = deref_aligned::<timespec>(data, *tp_offset, 1)?;
            Syscall {
                num: libc::SYS_clock_gettime,
                argv: [*clockid, tp as _],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [fd, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_close as _ => Syscall {
            num: libc::SYS_close,
            argv: [*fd],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [sockfd, addr_offset, addrlen, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_connect as _ => {
            let addr = deref_sockaddr_input(data, *addr_offset, *addrlen)?;
            Syscall {
                num: libc::SYS_connect,
                argv: [*sockfd, addr as _, *addrlen],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [oldfd, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_dup as _ => Syscall {
            num: libc::SYS_dup,
            argv: [*oldfd],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [oldfd, newfd, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_dup2 as _ => Syscall {
            num: libc::SYS_dup2,
            argv: [*oldfd, *newfd],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [oldfd, newfd, flags, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_dup3 as _ => Syscall {
            num: libc::SYS_dup3,
            argv: [*oldfd, *newfd, *flags],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [flags, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_epoll_create1 as _ => Syscall {
            num: libc::SYS_epoll_create1,
            argv: [*flags],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [epfd, op, fd, event_offset, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_epoll_ctl as _ => {
            let event = deref_aligned::<epoll_event>(data, *event_offset, 1)?;
            Syscall {
                num: libc::SYS_epoll_ctl,
                argv: [*epfd, *op, *fd, event as _],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [epfd, events_offset, maxevents, timeout, sigmask_offset, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_epoll_pwait as _ => {
            let events = deref_aligned::<epoll_event>(data, *events_offset, *maxevents)?;
            let sigmask = deref_aligned::<sigset_t>(data, *sigmask_offset, 1)?;
            Syscall {
                num: libc::SYS_epoll_pwait,
                argv: [*epfd, events as _, *maxevents, *timeout, sigmask as _],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [epfd, events_offset, maxevents, timeout, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_epoll_wait as _ => {
            let events = deref_aligned::<epoll_event>(data, *events_offset, *maxevents)?;
            Syscall {
                num: libc::SYS_epoll_wait,
                argv: [*epfd, events as _, *maxevents, *timeout],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [initval, flags, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_eventfd2 as _ => Syscall {
            num: libc::SYS_eventfd2,
            argv: [*initval, *flags],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [status, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_exit as _ => Syscall {
            num: libc::SYS_exit,
            argv: [*status],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [status, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_exit_group as _ => Syscall {
            num: libc::SYS_exit_group,
            argv: [*status],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [fd, cmd, arg, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_fcntl as _ => Syscall {
            num: libc::SYS_fcntl,
            argv: [*fd, *cmd, *arg],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [sockfd, addr_offset, addrlen_offset, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_getsockname as _ => {
            let (addr, addrlen) = deref_sockaddr_output(data, *addr_offset, *addrlen_offset)?;
            Syscall {
                num: libc::SYS_getsockname,
                argv: [*sockfd, addr as _, addrlen as _],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [fd, request, argp_offset, argp_len, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_ioctl as _ => {
            let argp = if *argp_offset == NULL {
                null_mut()
            } else {
                deref::<u8>(data, *argp_offset, *argp_len)?
            };
            Syscall {
                num: libc::SYS_ioctl,
                argv: [*fd, *request, argp as _],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [sockfd, backlog, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_listen as _ => Syscall {
            num: libc::SYS_listen,
            argv: [*sockfd, *backlog],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [req_offset, rem_offset, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_nanosleep as _ => {
            let req = deref_aligned::<timespec>(data, *req_offset, 1)?;
            let rem = if *rem_offset == NULL {
                null_mut()
            } else {
                deref_aligned::<timespec>(data, *rem_offset, 1)?
            };
            Syscall {
                num: libc::SYS_nanosleep,
                argv: [req as _, rem as _],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [pathname_offset, pathname_len, flags, mode, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_open as _ => {
            let pathname = deref::<u8>(data, *pathname_offset, *pathname_len)?;
            Syscall {
                num: libc::SYS_open,
                argv: [pathname as _, *flags, *mode],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [fds_offset, nfds, timeout, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_poll as _ => {
            let fds = deref_aligned::<pollfd>(data, *fds_offset, *nfds)?;
            Syscall {
                num: libc::SYS_poll,
                argv: [fds as _, *nfds, *timeout],
                ret: [ret],
            }
            .execute()
        }

        item::Syscall {
            num,
            argv: [fd, buf_offset, count, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_read as _ => {
            let buf = deref::<u8>(data, *buf_offset, *count)?;
            Syscall {
                num: libc::SYS_read,
                argv: [*fd, buf as _, *count],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [sockfd, buf_offset, len, flags, src_addr_offset, addrlen_offset],
            ret: [ret, ..],
        } if *num == libc::SYS_recvfrom as _ => {
            let buf = deref::<u8>(data, *buf_offset, *len)?;
            let (src_addr, addrlen) = if *src_addr_offset == NULL {
                (null_mut(), null_mut())
            } else {
                deref_sockaddr_output(data, *src_addr_offset, *addrlen_offset)?
            };
            Syscall {
                num: libc::SYS_recvfrom,
                argv: [*sockfd, buf as _, *len, *flags, src_addr as _, addrlen as _],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [sockfd, buf_offset, len, flags, dest_addr_offset, addrlen],
            ret: [ret, ..],
        } if *num == libc::SYS_sendto as _ => {
            let buf = deref::<u8>(data, *buf_offset, *len)?;
            let dest_addr = if *dest_addr_offset == NULL {
                null()
            } else {
                deref_sockaddr_input(data, *dest_addr_offset, *addrlen)?
            };
            Syscall {
                num: libc::SYS_sendto,
                argv: [*sockfd, buf as _, *len, *flags, dest_addr as _, *addrlen],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [sockfd, level, optname, optval_offset, optlen, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_setsockopt as _ => {
            let (optval, optlen) = if *optval_offset == NULL {
                (null_mut(), 0)
            } else {
                let optval = deref::<u8>(data, *optval_offset, *optlen)?;
                // We have no means to determine the actual alignment of type optval points to,
                // therefore ensure alignment of align_of::<usize>() is maintained and hope for the
                // best.
                if optval.align_offset(align_of::<usize>()) != 0 {
                    return Err(EFAULT);
                }
                (optval, *optlen)
            };
            Syscall {
                num: libc::SYS_setsockopt,
                argv: [*sockfd, *level, *optname, optval as _, optlen],
                ret: [ret],
            }
            .execute();
        }

        item::Syscall {
            num,
            argv: [domain, typ, protocol, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_socket as _ => Syscall {
            num: libc::SYS_socket,
            argv: [*domain, *typ, *protocol],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: _,
            ret: [ret, ..],
        } if *num == libc::SYS_sync as _ => Syscall {
            num: libc::SYS_sync,
            argv: [],
            ret: [ret],
        }
        .execute(),

        item::Syscall {
            num,
            argv: [fd, buf_offset, count, ..],
            ret: [ret, ..],
        } if *num == libc::SYS_write as _ => {
            let buf = deref::<u8>(data, *buf_offset, *count)?;
            Syscall {
                num: libc::SYS_write,
                argv: [*fd, buf as _, *count],
                ret: [ret],
            }
            .execute();
        }

        // Silently skip unsupported items
        _ => {}
    }
    Ok(())
}
