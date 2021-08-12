// SPDX-License-Identifier: Apache-2.0

//! Common syscall handling across shims.

mod base;
mod enarx;
mod file;
mod memory;
mod network;
mod process;
mod system;

pub use base::BaseSyscallHandler;
pub use enarx::EnarxSyscallHandler;
pub use file::FileSyscallHandler;
pub use memory::MemorySyscallHandler;
pub use network::NetworkSyscallHandler;
pub use process::ProcessSyscallHandler;
pub use system::SystemSyscallHandler;

use crate::untrusted::AddressValidator;
use crate::Result;
use core::convert::TryInto;
use primordial::Register;

/// `get_attestation` syscall number
///
/// See https://github.com/enarx/enarx-keepldr/issues/31
#[allow(dead_code)]
pub const SYS_ENARX_GETATT: i64 = 0xEA01;

/// Enarx syscall extension: get `MemInfo` from the host
#[allow(dead_code)]
pub const SYS_ENARX_MEM_INFO: i64 = 0xEA02;

/// Enarx syscall extension: request an additional memory region
#[allow(dead_code)]
pub const SYS_ENARX_BALLOON_MEMORY: i64 = 0xEA03;

/// Enarx syscall extension: CPUID
#[allow(dead_code)]
pub const SYS_ENARX_CPUID: i64 = 0xEA04;

/// Enarx syscall extension: Resume an enclave after an asynchronous exit
// Keep in sync with shim-sgx/src/start.S
#[allow(dead_code)]
pub const SYS_ENARX_ERESUME: i64 = -1;

/// `get_attestation` technology return value
///
/// See https://github.com/enarx/enarx-keepldr/issues/31
#[allow(dead_code)]
pub const SEV_TECH: usize = 1;

/// `get_attestation` technology return value
///
/// See https://github.com/enarx/enarx-keepldr/issues/31
#[allow(dead_code)]
pub const SGX_TECH: usize = 2;

/// Size in bytes of expected SGX Quote
// TODO: Determine length of Quote of PCK cert type
#[allow(dead_code)]
pub const SGX_QUOTE_SIZE: usize = 4598;

/// Size in bytes of expected SGX QE TargetInfo
#[allow(dead_code)]
pub const SGX_TI_SIZE: usize = 512;

/// Dummy value returned when daemon to return SGX TargetInfo is
/// not available on the system.
#[allow(dead_code)]
pub const SGX_DUMMY_TI: [u8; SGX_TI_SIZE] = [32u8; SGX_TI_SIZE];

/// Dummy value returned when daemon to return SGX Quote is not
/// available on the system.
#[allow(dead_code)]
pub const SGX_DUMMY_QUOTE: [u8; SGX_QUOTE_SIZE] = [44u8; SGX_QUOTE_SIZE];

// arch_prctl syscalls not available in the libc crate as of version 0.2.69
/// missing in libc
pub const ARCH_SET_GS: libc::c_int = 0x1001;
/// missing in libc
pub const ARCH_SET_FS: libc::c_int = 0x1002;
/// missing in libc
pub const ARCH_GET_FS: libc::c_int = 0x1003;
/// missing in libc
pub const ARCH_GET_GS: libc::c_int = 0x1004;

/// Fake pid returned by enarx
pub const FAKE_PID: usize = 1000;
/// Fake uid returned by enarx
pub const FAKE_UID: usize = 1000;
/// Fake gid returned by enarx
pub const FAKE_GID: usize = 1000;

/// not defined in libc
///
/// FIXME
pub struct KernelSigSet;

/// not defined in libc
///
/// FIXME
pub type KernelSigAction = [u64; 4];

/// A trait defining a shim syscall handler
///
/// Implemented for each shim. Some common methods are already implemented,
/// but can be overwritten with optimized versions.
pub trait SyscallHandler:
    Sized
    + AddressValidator
    + BaseSyscallHandler
    + MemorySyscallHandler
    + ProcessSyscallHandler
    + FileSyscallHandler
    + NetworkSyscallHandler
    + EnarxSyscallHandler
    + SystemSyscallHandler
{
    /// syscall
    #[cfg(target_arch = "x86_64")]
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
        let mut ret = self.do_syscall(a, b, c, d, e, f, nr);

        if nr < 0xEA00 {
            // Non Enarx syscalls don't use `ret[1]` and have
            // to return the original value of `rdx`.
            ret = ret.map(|ret| [ret[0], c]);
        }

        ret
    }

    /// syscall handling without architecture specific return handling
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn do_syscall(
        &mut self,
        a: Register<usize>,
        b: Register<usize>,
        c: Register<usize>,
        d: Register<usize>,
        e: Register<usize>,
        f: Register<usize>,
        nr: usize,
    ) -> Result {
        let ret = match nr as _ {
            // MemorySyscallHandler
            libc::SYS_brk => self.brk(a.into()),
            libc::SYS_mmap => self.mmap(
                a.into(),
                b.into(),
                c.try_into().map_err(|_| libc::EINVAL)?,
                usize::from(d) as _,
                usize::from(e) as _,
                f.into(),
            ),
            libc::SYS_munmap => self.munmap(a.into(), b.into()),
            libc::SYS_madvise => self.madvise(a.into(), b.into(), usize::from(c) as _),
            libc::SYS_mprotect => self.mprotect(a.into(), b.into(), usize::from(c) as _),

            // ProcessSyscallHandler
            libc::SYS_arch_prctl => self.arch_prctl(usize::from(a) as _, b.into()),
            libc::SYS_exit => self.exit(usize::from(a) as _),
            libc::SYS_exit_group => self.exit_group(usize::from(a) as _),
            libc::SYS_set_tid_address => self.set_tid_address(a.into()),
            libc::SYS_rt_sigaction => {
                self.rt_sigaction(usize::from(a) as _, b.into(), c.into(), d.into())
            }
            libc::SYS_rt_sigprocmask => {
                self.rt_sigprocmask(usize::from(a) as _, b.into(), c.into(), d.into())
            }
            libc::SYS_sigaltstack => self.sigaltstack(a.into(), b.into()),
            libc::SYS_getpid => self.getpid(),
            libc::SYS_getuid => self.getuid(),
            libc::SYS_getgid => self.getgid(),
            libc::SYS_geteuid => self.geteuid(),
            libc::SYS_getegid => self.getegid(),

            // SystemSyscallHandler
            libc::SYS_getrandom => self.getrandom(a.into(), b.into(), usize::from(c) as _),
            libc::SYS_clock_gettime => self.clock_gettime(usize::from(a) as _, b.into()),
            libc::SYS_uname => self.uname(a.into()),

            // FileSyscallHandler
            libc::SYS_close => self.close(a.try_into().map_err(|_| libc::EINVAL)?),
            libc::SYS_read => self.read(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_readv => self.readv(usize::from(a) as _, b.into(), usize::from(c) as _),
            libc::SYS_write => self.write(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_writev => self.writev(usize::from(a) as _, b.into(), usize::from(c) as _),
            libc::SYS_ioctl => self.ioctl(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_readlink => self.readlink(a.into(), b.into(), c.into()),
            libc::SYS_fstat => self.fstat(usize::from(a) as _, b.into()),
            libc::SYS_fcntl => self.fcntl(
                usize::from(a) as _,
                usize::from(b) as _,
                usize::from(c) as _,
            ),
            libc::SYS_poll => self.poll(a.into(), b.into(), usize::from(c) as _),
            libc::SYS_pipe => self.pipe(a.into()),
            libc::SYS_epoll_create1 => self.epoll_create1(a.try_into().map_err(|_| libc::EINVAL)?),
            libc::SYS_epoll_ctl => self.epoll_ctl(
                usize::from(a) as _,
                usize::from(b) as _,
                usize::from(c) as _,
                d.into(),
            ),
            libc::SYS_epoll_wait => self.epoll_wait(
                usize::from(a) as _,
                b.into(),
                usize::from(c) as _,
                usize::from(d) as _,
            ),
            libc::SYS_epoll_pwait => self.epoll_pwait(
                usize::from(a) as _,
                b.into(),
                usize::from(c) as _,
                usize::from(d) as _,
                e.into(),
            ),
            libc::SYS_eventfd2 => self.eventfd2(usize::from(a) as _, usize::from(b) as _),
            libc::SYS_dup => self.dup(usize::from(a) as _),
            libc::SYS_dup2 => self.dup2(usize::from(a) as _, usize::from(b) as _),
            libc::SYS_dup3 => self.dup3(
                usize::from(a) as _,
                usize::from(b) as _,
                usize::from(c) as _,
            ),

            // NetworkSyscallHandler
            libc::SYS_socket => self.socket(
                usize::from(a) as _,
                usize::from(b) as _,
                usize::from(c) as _,
            ),
            libc::SYS_bind => self.bind(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_listen => self.listen(usize::from(a) as _, usize::from(b) as _),
            libc::SYS_getsockname => self.getsockname(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_accept => self.accept(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_accept4 => {
                self.accept4(usize::from(a) as _, b.into(), c.into(), usize::from(d) as _)
            }
            libc::SYS_connect => self.connect(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_recvfrom => self.recvfrom(
                usize::from(a) as _,
                b.into(),
                c.into(),
                usize::from(d) as _,
                e.into(),
                f.into(),
            ),
            libc::SYS_sendto => self.sendto(
                usize::from(a) as _,
                b.into(),
                c.into(),
                usize::from(d) as _,
                e.into(),
                f.into(),
            ),
            libc::SYS_setsockopt => self.setsockopt(
                usize::from(a) as _,
                usize::from(b) as _,
                usize::from(c) as _,
                d.into(),
                usize::from(e) as _,
            ),

            SYS_ENARX_GETATT => self.get_attestation(a.into(), b.into(), c.into(), d.into()),

            _ => {
                self.unknown_syscall(a, b, c, d, e, f, nr);

                Err(libc::ENOSYS)
            }
        };

        ret
    }
}
