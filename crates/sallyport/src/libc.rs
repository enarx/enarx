// SPDX-License-Identifier: Apache-2.0

//! Definitions of upstream [libc] items used within the crate.

// We cannot use the libc crate directly.
// This is because the sallyport crate is a dependency of the enarx shims,
// which support the x86_64-unknown-none target,
// and the libc crate doesn't contain the proper symbols when compiled for that target
// (which is correct, as the "none" in our target triple's OS field indicates).
// Ideally we would not need to maintain these definitions ourselves;
// instead, the ideal solution would be for the official libc crate to be split
// into platform-specific crates, with the libc crate being a facade,
// and we could then depend on the Linux-specific crate directly.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_short, c_size_t, c_uint, c_ulong, c_void};

pub type blkcnt_t = i64;
pub type blksize_t = i64;
pub type clockid_t = i32;
pub type dev_t = u64;
pub type gid_t = u32;
pub type in_addr_t = u32;
pub type in_port_t = u16;
pub type ino_t = u64;
pub type mode_t = u32;
pub type nlink_t = u64;
pub type off_t = i64;
pub type pid_t = i32;
pub type sa_family_t = u16;
pub type socklen_t = u32;
pub type suseconds_t = i64;
pub type time_t = i64;
pub type uid_t = u32;
pub type Ioctl = i32;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct epoll_event {
    pub events: u32,
    pub u64: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: c_size_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}

#[repr(C)]
#[repr(align(4))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct pollfd {
    pub fd: c_int,
    pub events: c_short,
    pub revents: c_short,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sigset_t {
    __val: [c_ulong; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [c_char; 14],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    __ss_align: c_size_t,
    __ss_pad2: [u8; 128 - 2 * 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [c_char; 108],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct stack_t {
    pub ss_sp: *mut c_void,
    pub ss_flags: c_int,
    pub ss_size: c_size_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct stat {
    pub st_dev: dev_t,
    pub st_ino: ino_t,
    pub st_nlink: nlink_t,
    pub st_mode: mode_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    __pad0: c_int,
    pub st_rdev: dev_t,
    pub st_size: off_t,
    pub st_blksize: blksize_t,
    pub st_blocks: blkcnt_t,
    pub st_atime: time_t,
    pub st_atime_nsec: c_long,
    pub st_mtime: time_t,
    pub st_mtime_nsec: c_long,
    pub st_ctime: time_t,
    pub st_ctime_nsec: c_long,
    __unused: [c_long; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct timespec {
    pub tv_sec: time_t,
    pub tv_nsec: c_long,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct timeval {
    pub tv_sec: time_t,
    pub tv_usec: suseconds_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct utsname {
    pub sysname: [c_char; 65],
    pub nodename: [c_char; 65],
    pub release: [c_char; 65],
    pub version: [c_char; 65],
    pub machine: [c_char; 65],
    pub domainname: [c_char; 65],
}

pub const AF_INET: c_int = 2;
pub const CLOCK_MONOTONIC: clockid_t = 1;
pub const CLONE_VM: c_uint = 0x00000100;
pub const CLONE_FS: c_uint = 0x00000200;
pub const CLONE_FILES: c_uint = 0x00000400;
pub const CLONE_SIGHAND: c_uint = 0x00000800;
pub const CLONE_PIDFD: c_uint = 0x00001000;
pub const CLONE_PTRACE: c_uint = 0x00002000;
pub const CLONE_VFORK: c_uint = 0x00004000;
pub const CLONE_PARENT: c_uint = 0x00008000;
pub const CLONE_THREAD: c_uint = 0x00010000;
pub const CLONE_NEWNS: c_uint = 0x00020000;
pub const CLONE_SYSVSEM: c_uint = 0x00040000;
pub const CLONE_SETTLS: c_uint = 0x00080000;
pub const CLONE_PARENT_SETTID: c_uint = 0x00100000;
pub const CLONE_CHILD_CLEARTID: c_uint = 0x00200000;
pub const CLONE_DETACHED: c_uint = 0x00400000;
pub const CLONE_UNTRACED: c_uint = 0x00800000;
pub const CLONE_CHILD_SETTID: c_uint = 0x01000000;
pub const CLONE_NEWCGROUP: c_uint = 0x02000000;
pub const CLONE_NEWUTS: c_uint = 0x04000000;
pub const CLONE_NEWIPC: c_uint = 0x08000000;
pub const CLONE_NEWUSER: c_uint = 0x10000000;
pub const CLONE_NEWPID: c_uint = 0x20000000;
pub const CLONE_NEWNET: c_uint = 0x40000000;
pub const CLONE_IO: c_uint = 0x80000000;
pub const EACCES: c_int = 13;
pub const EAGAIN: c_int = 11;
pub const EBADF: c_int = 9;
pub const EBADFD: c_int = 77;
pub const EFAULT: c_int = 14;
pub const EINTR: c_int = 4;
pub const EINVAL: c_int = 22;
pub const EIO: c_int = 5;
pub const EMSGSIZE: c_int = 90;
pub const ENOENT: c_int = 2;
pub const ENOMEM: c_int = 12;
pub const ENOSYS: c_int = 38;
pub const ENOTSUP: c_int = 95;
pub const ENOTTY: c_int = 25;
pub const EOVERFLOW: c_int = 75;
pub const EPERM: c_int = 1;
pub const F_GETFD: c_int = 1;
pub const F_GETFL: c_int = 3;
pub const F_SETFD: c_int = 2;
pub const F_SETFL: c_int = 4;
pub const FIONBIO: Ioctl = 0x5421;
pub const FIONREAD: Ioctl = 0x541B;
pub const FUTEX_WAIT: c_int = 0;
pub const FUTEX_WAKE: c_int = 1;
pub const FUTEX_FD: c_int = 2;
pub const FUTEX_REQUEUE: c_int = 3;
pub const FUTEX_CMP_REQUEUE: c_int = 4;
pub const FUTEX_WAKE_OP: c_int = 5;
pub const FUTEX_LOCK_PI: c_int = 6;
pub const FUTEX_UNLOCK_PI: c_int = 7;
pub const FUTEX_TRYLOCK_PI: c_int = 8;
pub const FUTEX_WAIT_BITSET: c_int = 9;
pub const FUTEX_WAKE_BITSET: c_int = 10;
pub const FUTEX_WAIT_REQUEUE_PI: c_int = 11;
pub const FUTEX_CMP_REQUEUE_PI: c_int = 12;
pub const FUTEX_LOCK_PI2: c_int = 13;
pub const FUTEX_PRIVATE_FLAG: c_int = 128;
pub const GRND_NONBLOCK: c_uint = 1;
pub const GRND_RANDOM: c_uint = 2;
pub const MAP_ANONYMOUS: c_int = 32;
pub const MAP_PRIVATE: c_int = 2;
pub const MREMAP_DONTUNMAP: c_int = 4;
pub const MREMAP_FIXED: c_int = 2;
pub const MREMAP_MAYMOVE: c_int = 1;
pub const MSG_NOSIGNAL: c_int = 16384;
pub const O_APPEND: c_int = 1024;
pub const O_CLOEXEC: c_int = 0x80000;
pub const O_CREAT: c_int = 64;
pub const O_RDONLY: c_int = 0;
pub const O_RDWR: c_int = 2;
pub const O_WRONLY: c_int = 1;
pub const PROT_EXEC: c_int = 4;
pub const PROT_READ: c_int = 1;
pub const PROT_WRITE: c_int = 2;
pub const S_IFIFO: mode_t = 4096;
pub const SOCK_CLOEXEC: c_int = O_CLOEXEC;
pub const SOCK_STREAM: c_int = 1;
pub const SOL_SOCKET: c_int = 1;
pub const SO_RCVTIMEO: c_int = 20;
pub const SO_REUSEADDR: c_int = 2;
pub const STDERR_FILENO: c_int = 2;
pub const STDIN_FILENO: c_int = 0;
pub const STDOUT_FILENO: c_int = 1;
pub const SYS_accept: c_long = 43;
pub const SYS_accept4: c_long = 288;
pub const SYS_arch_prctl: c_long = 158;
pub const SYS_bind: c_long = 49;
pub const SYS_brk: c_long = 12;
pub const SYS_clock_getres: c_long = 229;
pub const SYS_clock_gettime: c_long = 228;
pub const SYS_clone: c_long = 56;
pub const SYS_close: c_long = 3;
pub const SYS_connect: c_long = 42;
pub const SYS_dup: c_long = 32;
pub const SYS_dup2: c_long = 33;
pub const SYS_dup3: c_long = 292;
pub const SYS_epoll_create1: c_long = 291;
pub const SYS_epoll_ctl: c_long = 233;
pub const SYS_epoll_pwait: c_long = 281;
pub const SYS_epoll_wait: c_long = 232;
pub const SYS_eventfd2: c_long = 290;
pub const SYS_exit: c_long = 60;
pub const SYS_exit_group: c_long = 231;
pub const SYS_fcntl: c_long = 72;
pub const SYS_fstat: c_long = 5;
pub const SYS_futex: c_long = 202;
pub const SYS_getegid: c_long = 108;
pub const SYS_geteuid: c_long = 107;
pub const SYS_getgid: c_long = 104;
pub const SYS_getpid: c_long = 39;
pub const SYS_getuid: c_long = 102;
pub const SYS_getrandom: c_long = 318;
pub const SYS_getsockname: c_long = 51;
pub const SYS_ioctl: c_long = 16;
pub const SYS_listen: c_long = 50;
pub const SYS_madvise: c_long = 28;
pub const SYS_mmap: c_long = 9;
pub const SYS_mprotect: c_long = 10;
pub const SYS_mremap: c_long = 25;
pub const SYS_munmap: c_long = 11;
pub const SYS_nanosleep: c_long = 35;
pub const SYS_open: c_long = 2;
pub const SYS_poll: c_long = 7;
pub const SYS_read: c_long = 0;
pub const SYS_readlink: c_long = 89;
pub const SYS_readv: c_long = 19;
pub const SYS_recvfrom: c_long = 45;
pub const SYS_rt_sigaction: c_long = 13;
pub const SYS_rt_sigprocmask: c_long = 14;
pub const SYS_set_tid_address: c_long = 218;
pub const SYS_sendto: c_long = 44;
pub const SYS_setsockopt: c_long = 54;
pub const SYS_sigaltstack: c_long = 131;
pub const SYS_socket: c_long = 41;
pub const SYS_sync: c_long = 162;
pub const SYS_uname: c_long = 63;
pub const SYS_write: c_long = 1;
pub const SYS_writev: c_long = 20;
pub const TIOCGWINSZ: Ioctl = 0x5413;

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Default)]
    pub struct CloneFlags: c_uint {
        const VM = CLONE_VM;
        const FS = CLONE_FS;
        const FILES = CLONE_FILES;
        const SIGHAND = CLONE_SIGHAND;
        const PIDFD = CLONE_PIDFD;
        const PTRACE = CLONE_PTRACE;
        const VFORK = CLONE_VFORK;
        const PARENT = CLONE_PARENT;
        const THREAD = CLONE_THREAD;
        const NEWNS = CLONE_NEWNS;
        const SYSVSEM = CLONE_SYSVSEM;
        const SETTLS = CLONE_SETTLS;
        const PARENT_SETTID = CLONE_PARENT_SETTID;
        const CHILD_CLEARTID = CLONE_CHILD_CLEARTID;
        const DETACHED = CLONE_DETACHED;
        const UNTRACED = CLONE_UNTRACED;
        const CHILD_SETTID = CLONE_CHILD_SETTID;
        const NEWCGROUP = CLONE_NEWCGROUP;
        const NEWUTS = CLONE_NEWUTS;
        const NEWIPC = CLONE_NEWIPC;
        const NEWUSER = CLONE_NEWUSER;
        const NEWPID = CLONE_NEWPID;
        const NEWNET = CLONE_NEWNET;
        const IO = CLONE_IO;
    }
}
