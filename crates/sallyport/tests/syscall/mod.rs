// SPDX-License-Identifier: Apache-2.0

use super::{recv_udp, run_test, write_tcp};

use core::ffi::{c_char, c_int};
use libc::{
    self, in_addr, iovec, pollfd, sockaddr, sockaddr_in, timespec, timeval, utsname, SYS_accept,
    SYS_accept4, SYS_bind, SYS_clock_getres, SYS_clock_gettime, SYS_close, SYS_fcntl, SYS_fstat,
    SYS_getegid, SYS_geteuid, SYS_getgid, SYS_getpid, SYS_getrandom, SYS_getsockname, SYS_listen,
    SYS_mremap, SYS_nanosleep, SYS_open, SYS_poll, SYS_read, SYS_readlink, SYS_readv, SYS_recvfrom,
    SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_sendto, SYS_set_tid_address, SYS_setsockopt,
    SYS_sigaltstack, SYS_socket, SYS_uname, SYS_write, SYS_writev, AF_INET, CLOCK_MONOTONIC,
    CLOCK_REALTIME, EACCES, EBADF, EBADFD, EINVAL, ENOENT, ENOSYS, ENOTSUP, F_GETFD, F_GETFL,
    F_SETFD, F_SETFL, GRND_RANDOM, MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE, MSG_NOSIGNAL,
    O_APPEND, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY, SIGCHLD, SIG_BLOCK, SOCK_CLOEXEC, SOCK_STREAM,
    SOL_SOCKET, SO_RCVTIMEO, SO_REUSEADDR, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO,
};
use std::env::temp_dir;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::mem::{size_of, transmute};
use std::net::{TcpListener, UdpSocket};
use std::os::unix::io::IntoRawFd;
use std::os::unix::prelude::AsRawFd;
use std::ptr::{null_mut, NonNull};
use std::slice;
use std::{mem, thread};

use sallyport::guest::syscall::types::SockaddrOutput;
use sallyport::guest::syscall::{FAKE_GID, FAKE_PID, FAKE_TID, FAKE_UID};
use sallyport::guest::{syscall, Handler, Platform};
use sallyport::item::syscall::sigaction;
use serial_test::serial;

fn syscall_socket(opaque: bool, platform: &impl Platform, exec: &mut impl Handler) -> c_int {
    let fd = if !opaque {
        exec.socket(AF_INET, SOCK_STREAM, 0)
            .expect("couldn't execute 'socket' syscall")
    } else {
        let [fd, ret1] = unsafe {
            exec.syscall(
                platform,
                [SYS_socket as _, AF_INET as _, SOCK_STREAM as _, 0, 0, 0, 0],
            )
        }
        .expect("couldn't execute 'socket' syscall");
        assert_eq!(ret1, 0);
        fd as _
    };
    assert!(fd >= 0);
    fd
}

fn syscall_recv(
    opaque: bool,
    platform: &impl Platform,
    exec: &mut impl Handler,
    fd: c_int,
    buf: &mut [u8],
) {
    let expected_len = buf.len();
    if !opaque {
        assert_eq!(exec.recv(fd, buf, 0), Ok(expected_len));
    } else {
        assert_eq!(
            unsafe {
                exec.syscall(
                    platform,
                    [
                        SYS_recvfrom as _,
                        fd as _,
                        buf.as_mut_ptr() as _,
                        expected_len,
                        0,
                        0,
                        0,
                    ],
                )
            },
            Ok([expected_len, 0])
        );
    }
}

fn dev_null() -> File {
    std::fs::File::open("/dev/null").unwrap()
}

#[test]
fn clock_getres() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        #[cfg(not(miri))]
        assert_eq!(unsafe { libc::clock_getres(CLOCK_REALTIME, null_mut()) }, 0);

        let expected = if cfg!(not(miri)) {
            let mut expected = unsafe { mem::zeroed() };
            assert_eq!(
                unsafe { libc::clock_getres(CLOCK_REALTIME, &mut expected as *mut _) },
                0
            );
            expected
        } else {
            unsafe { mem::zeroed() }
        };

        let mut res = unsafe { mem::zeroed::<timespec>() };
        if i % 2 == 0 {
            assert_eq!(
                handler.clock_getres(CLOCK_REALTIME, None),
                if cfg!(not(miri)) { Ok(()) } else { Err(ENOSYS) }
            );
            assert_eq!(
                handler.clock_getres(CLOCK_REALTIME, Some(unsafe { transmute(&mut res) })),
                if cfg!(not(miri)) { Ok(()) } else { Err(ENOSYS) }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_clock_getres as _,
                            CLOCK_REALTIME as _,
                            null_mut::<timespec>() as _,
                            0,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([0, 0])
                } else {
                    Err(ENOSYS)
                }
            );
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_clock_getres as _,
                            CLOCK_REALTIME as _,
                            &mut res as *mut _ as _,
                            0,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([0, 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        assert_eq!(res, expected);
    });
}

#[test]
fn clock_gettime() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        let start: timespec = if cfg!(not(miri)) {
            let mut start = unsafe { mem::zeroed() };
            assert_eq!(
                unsafe { libc::clock_gettime(CLOCK_MONOTONIC, &mut start as *mut _) },
                0
            );
            start
        } else {
            unsafe { mem::zeroed() }
        };

        let mut tp = unsafe { mem::zeroed::<timespec>() };
        if i % 2 == 0 {
            assert_eq!(
                handler.clock_gettime(CLOCK_MONOTONIC, unsafe { transmute(&mut tp) }),
                if cfg!(not(miri)) { Ok(()) } else { Err(ENOSYS) }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_clock_gettime as _,
                            CLOCK_MONOTONIC as _,
                            &mut tp as *mut _ as _,
                            0,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([0, 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        if cfg!(not(miri)) {
            assert!(tp.tv_sec > start.tv_sec || tp.tv_nsec > start.tv_nsec);
        } else {
            assert_eq!(tp, start);
        }
    });
}

#[test]
#[serial]
fn close() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        let path = temp_dir().join(format!("sallyport-test-close-{i}"));
        let c_path = CString::new(path.as_os_str().to_str().unwrap()).unwrap();

        // NOTE: `miri` only supports mode 0o666 at the time of writing
        // https://github.com/rust-lang/miri/blob/7a2f1cadcd5120c44eda3596053de767cd8173a2/src/shims/posix/fs.rs#L487-L493
        let fd = unsafe { libc::open(c_path.as_ptr(), O_RDWR | O_CREAT, 0o666) };
        if cfg!(not(miri)) {
            if i % 2 == 0 {
                assert_eq!(handler.close(fd), Ok(()));
            } else {
                assert_eq!(
                    unsafe { handler.syscall(platform, [SYS_close as _, fd as _, 0, 0, 0, 0, 0]) },
                    Ok([0, 0])
                );
            }
            assert_eq!(unsafe { libc::close(fd) }, -1);
            assert_eq!(unsafe { libc::__errno_location().read() }, EBADF);
        } else if i % 2 == 0 {
            assert_eq!(handler.close(fd), Err(ENOSYS));
        } else {
            assert_eq!(
                unsafe { handler.syscall(platform, [SYS_close as _, fd as _, 0, 0, 0, 0, 0]) },
                Err(ENOSYS)
            );
        }
    })
}

#[test]
#[serial]
fn fcntl() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        if i % 2 == 0 {
            assert_eq!(
                handler.fcntl(STDIN_FILENO, F_GETFL, 0),
                Ok(O_RDWR | O_APPEND)
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [SYS_fcntl as _, STDIN_FILENO as _, F_GETFL as _, 0, 0, 0, 0],
                    )
                },
                Ok([(O_RDWR | O_APPEND) as _, 0])
            );
        }

        for fd in [STDOUT_FILENO, STDERR_FILENO] {
            if i % 2 == 0 {
                assert_eq!(handler.fcntl(fd, F_GETFL, 0), Ok(O_WRONLY));
            } else {
                assert_eq!(
                    unsafe {
                        handler.syscall(
                            platform,
                            [SYS_fcntl as _, fd as _, F_GETFL as _, 0, 0, 0, 0],
                        )
                    },
                    Ok([O_WRONLY as _, 0])
                );
            }
        }

        for fd in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] {
            if i % 2 == 0 {
                assert_eq!(handler.fcntl(fd, F_GETFD, 0), Err(EINVAL));
            } else {
                assert_eq!(
                    unsafe {
                        handler.syscall(
                            platform,
                            [SYS_fcntl as _, fd as _, F_GETFD as _, 0, 0, 0, 0],
                        )
                    },
                    Err(EINVAL),
                );
            }
        }

        let file = File::create(temp_dir().join(format!("sallyport-test-fcntl-{i}"))).unwrap();
        let fd = file.as_raw_fd();

        for cmd in [F_GETFD] {
            if i % 2 == 0 {
                assert_eq!(
                    handler.fcntl(fd, cmd, 0),
                    if cfg!(not(miri)) {
                        Ok(unsafe { libc::fcntl(fd, cmd) })
                    } else {
                        Err(ENOSYS)
                    }
                );
            } else {
                assert_eq!(
                    unsafe {
                        handler.syscall(platform, [SYS_fcntl as _, fd as _, cmd as _, 0, 0, 0, 0])
                    },
                    if cfg!(not(miri)) {
                        Ok([unsafe { libc::fcntl(fd, cmd) } as _, 0])
                    } else {
                        Err(ENOSYS)
                    }
                );
            }
        }
        for (cmd, arg) in [(F_SETFD, 1), (F_GETFL, 0), (F_SETFL, 1)] {
            if i % 2 == 0 {
                assert_eq!(
                    handler.fcntl(fd, cmd, arg),
                    if cfg!(not(miri)) {
                        Ok(unsafe { libc::fcntl(fd, cmd, arg) })
                    } else {
                        Err(ENOSYS)
                    }
                );
            } else {
                assert_eq!(
                    unsafe {
                        handler.syscall(
                            platform,
                            [SYS_fcntl as _, fd as _, cmd as _, arg as _, 0, 0, 0],
                        )
                    },
                    if cfg!(not(miri)) {
                        Ok([unsafe { libc::fcntl(fd, cmd, arg) } as _, 0])
                    } else {
                        Err(ENOSYS)
                    }
                );
            }
        }
    });
}

#[test]
#[serial]
fn fstat() {
    let file = File::create(temp_dir().join("sallyport-test-fstat")).unwrap();
    let fd = file.as_raw_fd();

    run_test(2, [0xff; 16], move |i, platform, handler| {
        let mut fd_stat = unsafe { mem::zeroed() };
        if i % 2 == 0 {
            assert_eq!(handler.fstat(fd, &mut fd_stat), Err(EBADFD));
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_fstat as _,
                            fd as _,
                            &mut fd_stat as *mut _ as _,
                            0,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                Err(EBADFD)
            );
        }

        for fd in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] {
            let mut stat = unsafe { mem::zeroed() };
            if i % 2 == 0 {
                assert_eq!(handler.fstat(fd, &mut stat), Ok(()));
            } else {
                assert_eq!(
                    unsafe {
                        handler.syscall(
                            platform,
                            [
                                SYS_fstat as _,
                                fd as _,
                                &mut stat as *mut _ as _,
                                0,
                                0,
                                0,
                                0,
                            ],
                        )
                    },
                    Ok([0, 0])
                );
            }
        }
    });
    let _ = file;
}

#[test]
fn getegid() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        if i % 2 == 0 {
            assert_eq!(handler.getegid(), Ok(FAKE_GID));
        } else {
            assert_eq!(
                unsafe { handler.syscall(platform, [SYS_getegid as _, 0, 0, 0, 0, 0, 0,],) },
                Ok([FAKE_GID as _, 0])
            );
        }
    });
}

#[test]
fn geteuid() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        if i % 2 == 0 {
            assert_eq!(handler.geteuid(), Ok(FAKE_UID));
        } else {
            assert_eq!(
                unsafe { handler.syscall(platform, [SYS_geteuid as _, 0, 0, 0, 0, 0, 0,],) },
                Ok([FAKE_UID as _, 0])
            );
        }
    });
}

#[test]
fn getgid() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        if i % 2 == 0 {
            assert_eq!(handler.getgid(), Ok(FAKE_GID));
        } else {
            assert_eq!(
                unsafe { handler.syscall(platform, [SYS_getgid as _, 0, 0, 0, 0, 0, 0,],) },
                Ok([FAKE_GID as _, 0])
            );
        }
    });
}

#[test]
fn getpid() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        if i % 2 == 0 {
            assert_eq!(handler.getpid(), Ok(FAKE_PID));
        } else {
            assert_eq!(
                unsafe { handler.syscall(platform, [SYS_getpid as _, 0, 0, 0, 0, 0, 0,],) },
                Ok([FAKE_PID as _, 0])
            );
        }
    });
}

#[test]
#[serial]
#[cfg_attr(miri, ignore)]
fn getrandom() {
    run_test(1, [0xff; 16], move |_, platform, handler| {
        const LEN: usize = 64;

        let mut buf = [0u8; LEN];
        assert_eq!(handler.getrandom(&mut buf, GRND_RANDOM), Ok(LEN));
        assert_ne!(buf, [0u8; LEN]);

        let mut buf_2 = buf;
        assert_eq!(
            unsafe {
                handler.syscall(
                    platform,
                    [
                        SYS_getrandom as _,
                        buf_2.as_mut_ptr() as _,
                        LEN,
                        GRND_RANDOM as _,
                        0,
                        0,
                        0,
                    ],
                )
            },
            Ok([LEN, 0])
        );
        assert_ne!(buf_2, [0u8; LEN]);
        assert_ne!(buf_2, buf);
    });
}

#[test]
fn mremap() {
    let mem = [0u8; 4096];

    run_test(2, [0xff; 0], move |i, platform, handler| {
        if i % 2 == 0 {
            assert_eq!(
                handler.mremap(
                    platform,
                    NonNull::new(mem.as_ptr() as _).unwrap(),
                    1,
                    2,
                    None
                ),
                Err(ENOTSUP)
            );
        } else {
            for (flags, new_address, result) in [
                (0, 0, Err(ENOTSUP)),
                (0, 1, Err(EINVAL)),
                (0xffff, 0, Err(EINVAL)),
                (MREMAP_MAYMOVE, 0xffff, Err(EINVAL)),
                (MREMAP_MAYMOVE, 0, Err(ENOSYS)),
                (MREMAP_DONTUNMAP, 0, Err(EINVAL)),
                (MREMAP_FIXED, 0xffff, Err(EINVAL)),
                (MREMAP_MAYMOVE | MREMAP_FIXED, 0, Err(EINVAL)),
                (MREMAP_MAYMOVE | MREMAP_FIXED, 0xffff, Err(ENOTSUP)),
                (MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0xffff, Err(EINVAL)),
                (MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0, Err(ENOSYS)),
                (
                    MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
                    0,
                    Err(EINVAL),
                ),
                (
                    MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
                    0xffff,
                    Err(ENOTSUP),
                ),
            ] {
                assert_eq!(
                    unsafe {
                        handler.syscall(
                            platform,
                            [
                                SYS_mremap as _,
                                mem.as_ptr() as _,
                                1,
                                2,
                                flags as _,
                                new_address,
                                0,
                            ],
                        )
                    },
                    result
                );
            }
        }
    });
}

#[test]
#[serial]
fn nanosleep() {
    run_test(2, [0xff; 32], move |i, platform, handler| {
        let req = timespec {
            tv_sec: 0,
            tv_nsec: 1,
        };
        if i % 2 == 0 {
            assert_eq!(
                handler.nanosleep(unsafe { transmute(&req) }, None),
                if cfg!(not(miri)) { Ok(()) } else { Err(ENOSYS) }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_nanosleep as _,
                            &req as *const _ as _,
                            null_mut() as *mut timespec as _,
                            0,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([0, 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }

        let mut rem = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if i % 2 == 0 {
            assert_eq!(
                handler.nanosleep(
                    unsafe { transmute(&req) },
                    Some(unsafe { transmute(&mut rem) })
                ),
                if cfg!(not(miri)) { Ok(()) } else { Err(ENOSYS) }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_nanosleep as _,
                            &req as *const _ as _,
                            &mut rem as *mut _ as _,
                            0,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([0, 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        assert_eq!(
            rem,
            timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }
        )
    });
}

#[test]
#[serial]
fn open() {
    run_test(2, [0xff; 32], move |i, platform, handler| {
        let libc_ret = unsafe { libc::open(b"/etc/resolv.conf\0".as_ptr() as _, O_RDONLY, 0o666) }; // NOTE: mode argument is ignored in this case, but specified to satisfy miri

        if i % 2 == 0 {
            assert_eq!(handler.open(b"/etc/passwd\0", O_RDONLY, None), Err(EACCES));
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_open as _,
                            b"/etc/passwd\0".as_ptr() as _,
                            O_RDONLY as _,
                            0,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                Err(EACCES)
            );
        }

        if i % 2 == 0 {
            let ret = handler.open(b"/etc/resolv.conf\0", O_RDONLY, None);
            if cfg!(not(miri)) {
                if libc_ret < 0 {
                    assert_eq!(ret, Err(-libc_ret));
                } else {
                    assert!(ret.is_ok());
                    assert_ne!(ret.unwrap(), libc_ret);
                }
            } else {
                assert_eq!(ret, Err(ENOSYS));
            }
        } else {
            let ret = unsafe {
                handler.syscall(
                    platform,
                    [
                        SYS_open as _,
                        b"/etc/resolv.conf\0".as_ptr() as _,
                        O_RDONLY as _,
                        0,
                        0,
                        0,
                        0,
                    ],
                )
            };
            if cfg!(not(miri)) {
                if libc_ret < 0 {
                    assert_eq!(ret, Err(-libc_ret));
                } else {
                    assert!(ret.is_ok());
                    assert_ne!(ret.unwrap(), [libc_ret as _, 0]);
                }
                assert!(ret.is_ok());
            } else {
                assert_eq!(ret, Err(ENOSYS));
            }
        }
    });
}

#[test]
#[serial]
fn poll() {
    let dev_null_0 = dev_null().into_raw_fd();
    let dev_null_1 = dev_null().into_raw_fd();
    let dev_null_2 = dev_null().into_raw_fd();

    run_test(2, [0xff; 16], move |i, platform, handler| {
        let mut fds: [pollfd; 3] = [
            pollfd {
                fd: dev_null_0,
                events: 0,
                revents: 0,
            },
            pollfd {
                fd: dev_null_1,
                events: 0,
                revents: 0,
            },
            pollfd {
                fd: dev_null_2,
                events: 0,
                revents: 0,
            },
        ];

        if i % 2 == 0 {
            assert_eq!(
                handler.poll(unsafe { transmute::<_, &mut [_; 3]>(&mut fds) }, 0),
                if cfg!(not(miri)) { Ok(0) } else { Err(ENOSYS) }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [SYS_poll as _, fds.as_mut_ptr() as _, fds.len(), 0, 0, 0, 0],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([0, 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
    });
}

#[test]
#[serial]
fn read() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        const EXPECTED: &str = "read";
        let path = temp_dir().join(format!("sallyport-test-read-{i}"));
        write!(&mut File::create(&path).unwrap(), "{EXPECTED}").unwrap();

        let mut buf = [0u8; EXPECTED.len()];

        let file = File::open(&path).unwrap();
        if i % 2 == 0 {
            assert_eq!(
                handler.read(file.as_raw_fd(), &mut buf),
                if cfg!(not(miri)) {
                    Ok(EXPECTED.len())
                } else {
                    Err(ENOSYS)
                }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_read as _,
                            file.as_raw_fd() as _,
                            buf.as_mut_ptr() as _,
                            EXPECTED.len(),
                            0,
                            0,
                            0,
                        ],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([EXPECTED.len(), 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        if cfg!(not(miri)) {
            assert_eq!(buf, EXPECTED.as_bytes());
        }
    });
}

#[test]
fn readlink() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        const EXPECTED: &[u8] = b"/init\0";
        let mut buf = [0u8; EXPECTED.len()];

        if i % 2 == 0 {
            assert_eq!(handler.readlink(b"/proc/self\0", &mut buf), Err(ENOENT));
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_readlink as _,
                            b"/proc/self\0".as_ptr() as _,
                            buf.as_mut_ptr() as _,
                            EXPECTED.len(),
                            0,
                            0,
                            0,
                        ],
                    )
                },
                Err(ENOENT)
            );
        }
        assert_eq!(buf, [0u8; 6]);

        if i % 2 == 0 {
            assert_eq!(
                handler.readlink(b"/proc/self/exe\0", &mut buf),
                Ok(EXPECTED.len())
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_readlink as _,
                            b"/proc/self/exe\0".as_ptr() as _,
                            buf.as_mut_ptr() as _,
                            EXPECTED.len(),
                            0,
                            0,
                            0,
                        ],
                    )
                },
                Ok([EXPECTED.len(), 0])
            );
        }
        assert_eq!(buf, EXPECTED)
    });
}

#[test]
#[serial]
fn readv() {
    run_test(2, [0xff; 14], move |i, platform, handler| {
        const EXPECTED: [&str; 3] = ["012", "345", "67"];
        const CONTENTS: &str = "012345678012345678";
        let path = temp_dir().join("sallyport-test-readv");
        write!(&mut File::create(&path).unwrap(), "{CONTENTS}").unwrap();

        let mut one = [0u8; EXPECTED[0].len()];
        let mut two = [0u8; EXPECTED[1].len()];
        let mut three = [0u8; EXPECTED[2].len() + 2];

        let mut four = [0u8; 0xffff]; // does not fit in the block

        let file = File::open(&path).unwrap();
        if i % 2 == 0 {
            assert_eq!(
                handler.readv(
                    file.as_raw_fd() as _,
                    &mut [
                        &mut [],
                        &mut one[..],
                        &mut [],
                        &mut two[..],
                        &mut three[..],
                        &mut four[..]
                    ],
                ),
                if cfg!(not(miri)) {
                    Ok(EXPECTED[0].len() + EXPECTED[1].len() + EXPECTED[2].len())
                } else {
                    Err(ENOSYS)
                }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_readv as _,
                            file.as_raw_fd() as _,
                            [
                                iovec {
                                    iov_base: one.as_mut_ptr() as _,
                                    iov_len: 0,
                                },
                                iovec {
                                    iov_base: one.as_mut_ptr() as _,
                                    iov_len: one.len(),
                                },
                                iovec {
                                    iov_base: two.as_mut_ptr() as _,
                                    iov_len: 0,
                                },
                                iovec {
                                    iov_base: two.as_mut_ptr() as _,
                                    iov_len: two.len(),
                                },
                                iovec {
                                    iov_base: three.as_mut_ptr() as _,
                                    iov_len: three.len(),
                                },
                                iovec {
                                    iov_base: four.as_mut_ptr() as _,
                                    iov_len: four.len(),
                                },
                            ]
                            .as_mut_ptr() as _,
                            6,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([EXPECTED[0].len() + EXPECTED[1].len() + EXPECTED[2].len(), 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        if cfg!(not(miri)) {
            assert_eq!(one, EXPECTED[0].as_bytes());
            assert_eq!(two, EXPECTED[1].as_bytes());
            assert_eq!(&three[..EXPECTED[2].len()], EXPECTED[2].as_bytes());
            assert_eq!(four, [0u8; 0xffff]);
        }
    });
}

#[test]
#[serial]
#[cfg_attr(miri, ignore)]
fn tcp_server() {
    run_test(4, [0xff; 32], move |i, platform, handler| {
        let sockfd = syscall_socket(i % 2 != 0, platform, handler);
        let optval = 1 as c_int;
        if i % 2 == 0 {
            assert_eq!(
                handler.setsockopt(sockfd, SOL_SOCKET as _, SO_REUSEADDR as _, Some(&optval)),
                Ok(0)
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_setsockopt as _,
                            sockfd as _,
                            SOL_SOCKET as _,
                            SO_REUSEADDR as _,
                            &optval as *const _ as _,
                            size_of::<c_int>(),
                            0,
                        ],
                    )
                },
                Ok([0, 0])
            );
        }

        let rcv_timeout = timeval {
            tv_sec: 1,
            tv_usec: 2,
        };
        if i % 2 == 0 {
            assert_eq!(
                handler.setsockopt(
                    sockfd,
                    SOL_SOCKET as _,
                    SO_RCVTIMEO as _,
                    Some(&rcv_timeout)
                ),
                Ok(0)
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_setsockopt as _,
                            sockfd as _,
                            SOL_SOCKET as _,
                            SO_RCVTIMEO as _,
                            &rcv_timeout as *const _ as _,
                            size_of::<timeval>(),
                            0,
                        ],
                    )
                },
                Ok([0, 0])
            );
        }

        let bind_addr = sockaddr_in {
            sin_family: AF_INET as _,
            sin_port: 0,
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            ..unsafe { mem::zeroed() }
        };
        if i % 2 == 0 {
            assert_eq!(
                handler.bind(sockfd, unsafe {
                    transmute::<_, &sallyport::libc::sockaddr_in>(&bind_addr)
                }),
                Ok(())
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_bind as _,
                            sockfd as _,
                            &bind_addr as *const _ as _,
                            size_of::<sockaddr_in>(),
                            0,
                            0,
                            0,
                        ],
                    )
                },
                Ok([0, 0])
            );
        }
        assert_eq!(
            bind_addr,
            sockaddr_in {
                sin_family: AF_INET as _,
                sin_port: 0,
                sin_addr: in_addr {
                    s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                },
                ..unsafe { mem::zeroed() }
            }
        );

        if i % 2 == 0 {
            assert_eq!(handler.listen(sockfd, 128), Ok(()));
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(platform, [SYS_listen as _, sockfd as _, 128, 0, 0, 0, 0])
                },
                Ok([0, 0])
            );
        }

        let mut addr: sockaddr_in = unsafe { mem::zeroed() };
        let mut addrlen = size_of::<sockaddr_in>() as _;
        if i % 2 == 0 {
            assert_eq!(
                handler.getsockname(sockfd, (&mut addr, &mut addrlen)),
                Ok(())
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_getsockname as _,
                            sockfd as _,
                            &mut addr as *mut _ as _,
                            &mut addrlen as *mut _ as _,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                Ok([0, 0])
            );
        }
        assert_eq!(addrlen, size_of::<sockaddr_in>() as _);
        assert_ne!(
            addr,
            sockaddr_in {
                sin_family: AF_INET as _,
                sin_port: 0,
                sin_addr: in_addr {
                    s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                },
                ..unsafe { mem::zeroed() }
            }
        );
        let addr = addr;

        const EXPECTED: &str = "tcp";
        let client = thread::Builder::new()
            .name("client".into())
            .spawn(move || {
                write_tcp(
                    ("127.0.0.1", u16::from_be(addr.sin_port)),
                    EXPECTED.as_bytes(),
                );
            })
            .expect("couldn't spawn client thread");

        let mut accept_addr: sockaddr = unsafe { mem::zeroed() };
        let mut accept_addrlen = size_of::<sockaddr>() as _;

        // NOTE: libstd sets `SOCK_CLOEXEC`.
        let accept_sockfd = match i % 4 {
            0 => handler
                .accept4(
                    sockfd,
                    Some((&mut accept_addr, &mut accept_addrlen)),
                    SOCK_CLOEXEC,
                )
                .expect("couldn't `accept4` client connection"),
            1 => {
                let [sockfd, ret1] = unsafe {
                    handler
                        .syscall(
                            platform,
                            [
                                SYS_accept4 as _,
                                sockfd as _,
                                &mut accept_addr as *mut _ as _,
                                &mut accept_addrlen as *mut _ as _,
                                SOCK_CLOEXEC as _,
                                0,
                                0,
                            ],
                        )
                        .expect("couldn't `accept4` client connection")
                };
                assert_eq!(ret1, 0);
                sockfd as _
            }
            2 => handler
                .accept(sockfd, Some((&mut accept_addr, &mut accept_addrlen)))
                .expect("couldn't `accept` client connection"),
            _ => {
                let [sockfd, ret1] = unsafe {
                    handler
                        .syscall(
                            platform,
                            [
                                SYS_accept as _,
                                sockfd as _,
                                &mut accept_addr as *mut _ as _,
                                &mut accept_addrlen as *mut _ as _,
                                0,
                                0,
                                0,
                            ],
                        )
                        .expect("couldn't `accept` client connection")
                };
                assert_eq!(ret1, 0);
                sockfd as _
            }
        };
        assert!(accept_sockfd >= 0);

        let mut buf = [0u8; EXPECTED.len()];
        syscall_recv(i % 2 != 0, platform, handler, accept_sockfd, &mut buf);
        assert_eq!(buf, EXPECTED.as_bytes());
        client.join().expect("couldn't join client thread");
    });
}

#[test]
#[serial]
#[cfg_attr(miri, ignore)]
fn recv() {
    const EXPECTED: &str = "recv";

    run_test(2, [0xff; 32], move |i, platform, handler| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("couldn't bind to address");
        let addr = listener.local_addr().unwrap();

        let client = thread::spawn(move || {
            write_tcp(addr, EXPECTED.as_bytes());
        });
        let stream = listener.accept().expect("couldn't accept connection").0;

        let mut buf = [0u8; EXPECTED.len()];
        syscall_recv(i % 2 != 0, platform, handler, stream.as_raw_fd(), &mut buf);
        assert_eq!(buf, EXPECTED.as_bytes());
        client.join().expect("couldn't join client thread");
    });
}

#[test]
#[serial]
#[cfg_attr(miri, ignore)]
fn recvfrom() {
    const EXPECTED: &str = "recvfrom";

    run_test(2, [0xff; 32], move |i, platform, handler| {
        let dest_socket = UdpSocket::bind("127.0.0.1:0").expect("couldn't bind to address");
        let dest_addr = dest_socket.local_addr().unwrap();

        let src_socket = UdpSocket::bind("127.0.0.1:0").expect("couldn't bind to address");
        let src_port = src_socket.local_addr().unwrap().port();

        let client = thread::Builder::new()
            .name("client".into())
            .spawn(move || {
                assert_eq!(
                    src_socket
                        .send_to(EXPECTED.as_bytes(), dest_addr)
                        .expect("couldn't send data"),
                    EXPECTED.len()
                );
            })
            .expect("couldn't spawn client thread");

        let mut buf = [0u8; EXPECTED.len()];
        let mut src_addr: sockaddr_in = unsafe { mem::zeroed() };
        let src_addr_bytes = unsafe {
            slice::from_raw_parts_mut(&mut src_addr as *mut _ as _, size_of::<sockaddr_in>())
        };
        let mut addrlen = src_addr_bytes.len() as _;
        if i % 2 == 0 {
            assert_eq!(
                handler.recvfrom(
                    dest_socket.as_raw_fd(),
                    &mut buf,
                    0,
                    SockaddrOutput::new(src_addr_bytes, &mut addrlen),
                ),
                Ok(EXPECTED.len())
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_recvfrom as _,
                            dest_socket.as_raw_fd() as _,
                            buf.as_mut_ptr() as _,
                            EXPECTED.len(),
                            0,
                            src_addr_bytes.as_mut_ptr() as _,
                            &mut addrlen as *mut _ as _,
                        ],
                    )
                },
                Ok([EXPECTED.len(), 0])
            );
        }
        assert_eq!(buf, EXPECTED.as_bytes());
        assert_eq!(
            src_addr,
            sockaddr_in {
                sin_family: AF_INET as _,
                sin_port: src_port.to_be(),
                sin_addr: in_addr {
                    s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                },
                ..unsafe { mem::zeroed() }
            },
        );
        assert_eq!(addrlen, size_of::<sockaddr_in>() as _);
        client.join().expect("couldn't join client thread");
    });
}

#[test]
fn rt_sigaction() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        let act = [0, 1, 2, 3];
        let act_2 = [3, 2, 1, 0];
        if i % 2 == 0 {
            let mut oldact = None;
            assert_eq!(
                handler.rt_sigaction(SIGCHLD, Some(&act), Some(&mut oldact), 8),
                Ok(())
            );
            assert_eq!(oldact, None);

            assert_eq!(
                handler.rt_sigaction(SIGCHLD, Some(&act_2), Some(&mut oldact), 8),
                Ok(())
            );
            assert_eq!(oldact, Some(act));

            assert_eq!(handler.rt_sigaction(SIGCHLD, None, None, 8), Ok(()));
            assert_eq!(handler.rt_sigaction(SIGCHLD, None, None, 4), Err(EINVAL));
        } else {
            let mut oldact: sigaction = [0; 4];
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_rt_sigaction as _,
                            SIGCHLD as _,
                            &act as *const _ as _,
                            &mut oldact as *mut _ as _,
                            8,
                            0,
                            0,
                        ],
                    )
                },
                Ok([0, 0])
            );
            assert_eq!(oldact, [0; 4]);

            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_rt_sigaction as _,
                            SIGCHLD as _,
                            &act_2 as *const _ as _,
                            &mut oldact as *mut _ as _,
                            8,
                            0,
                            0,
                        ],
                    )
                },
                Ok([0, 0])
            );
            assert_eq!(oldact, act);

            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [SYS_rt_sigaction as _, SIGCHLD as _, 0, 0, 8, 0, 0],
                    )
                },
                Ok([0, 0])
            );

            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [SYS_rt_sigaction as _, SIGCHLD as _, 0, 0, 4, 0, 0],
                    )
                },
                Err(EINVAL)
            );
        }
    });
}

#[test]
fn rt_sigprocmask() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        if i % 2 == 0 {
            assert_eq!(handler.rt_sigprocmask(SIG_BLOCK, None, None, 1), Ok(()));
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [SYS_rt_sigprocmask as _, SIG_BLOCK as _, 0, 0, 1, 0, 0],
                    )
                },
                Ok([0, 0])
            );
        }
    });
}

#[test]
#[serial]
#[cfg_attr(miri, ignore)]
fn send() {
    const EXPECTED: &str = "send";

    run_test(2, [0xff; 32], move |i, platform, handler| {
        let dest_socket = UdpSocket::bind("127.0.0.1:0").expect("couldn't bind to address");
        let dest_addr = dest_socket.local_addr().unwrap();

        let server = thread::Builder::new()
            .name("server".into())
            .spawn(move || recv_udp(dest_socket, EXPECTED))
            .expect("couldn't spawn server thread");

        let src_socket = UdpSocket::bind("127.0.0.1:0").expect("couldn't bind to address");
        src_socket
            .connect(dest_addr)
            .expect("couldn't connect to destination address");
        if i % 2 == 0 {
            assert_eq!(
                handler.send(src_socket.as_raw_fd(), EXPECTED.as_bytes(), MSG_NOSIGNAL),
                Ok(EXPECTED.len())
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_sendto as _,
                            src_socket.as_raw_fd() as _,
                            EXPECTED.as_ptr() as _,
                            EXPECTED.len(),
                            MSG_NOSIGNAL as _,
                            0,
                            0,
                        ],
                    )
                },
                Ok([EXPECTED.len(), 0])
            );
        }
        server.join().expect("couldn't join server thread");
    });
}

#[test]
#[serial]
#[cfg_attr(miri, ignore)]
fn sendto() {
    const EXPECTED: &str = "sendto";

    run_test(2, [0xff; 32], move |i, platform, handler| {
        let dest_socket = UdpSocket::bind("127.0.0.1:0").expect("couldn't bind to address");
        let dest_port = dest_socket.local_addr().unwrap().port();

        let server = thread::Builder::new()
            .name("server".into())
            .spawn(move || recv_udp(dest_socket, EXPECTED))
            .expect("couldn't spawn server thread");

        let src_socket = UdpSocket::bind("127.0.0.1:0").expect("couldn't bind to address");
        let dest_addr = sockaddr_in {
            sin_family: AF_INET as _,
            sin_port: dest_port.to_be(),
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            ..unsafe { mem::zeroed() }
        };
        if i % 2 == 0 {
            assert_eq!(
                handler.sendto(
                    src_socket.as_raw_fd(),
                    EXPECTED.as_bytes(),
                    MSG_NOSIGNAL,
                    unsafe { transmute::<_, &sallyport::libc::sockaddr_in>(&dest_addr) },
                ),
                Ok(EXPECTED.len())
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_sendto as _,
                            src_socket.as_raw_fd() as _,
                            EXPECTED.as_ptr() as _,
                            EXPECTED.len(),
                            MSG_NOSIGNAL as _,
                            &dest_addr as *const _ as _,
                            size_of::<sockaddr_in>(),
                        ],
                    )
                },
                Ok([EXPECTED.len(), 0])
            );
        }
        server.join().expect("couldn't join server thread");
    });
}

#[test]
fn set_tid_address() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        let mut tidptr = 0;
        if i % 2 == 0 {
            assert_eq!(handler.set_tid_address(&mut tidptr), Ok(FAKE_TID));
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_set_tid_address as _,
                            &mut tidptr as *mut _ as _,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                Ok([FAKE_TID as _, 0])
            );
        }
    });
}

#[test]
fn sigaltstack() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        if i % 2 == 0 {
            assert_eq!(handler.sigaltstack(None, None), Ok(()));
        } else {
            assert_eq!(
                unsafe { handler.syscall(platform, [SYS_sigaltstack as _, 0, 0, 0, 0, 0, 0],) },
                Ok([0, 0])
            );
        }
    });
}

#[test]
#[serial]
fn sync_read_close() {
    run_test(1, [0xff; 64], move |_, _, handler| {
        const EXPECTED: &str = "sync-read-close";
        let path = temp_dir().join("sallyport-test-sync-read-close");
        write!(&mut File::create(&path).unwrap(), "{EXPECTED}").unwrap();

        let c_path = CString::new(path.as_os_str().to_str().unwrap()).unwrap();
        let fd = unsafe { libc::open(c_path.as_ptr(), O_RDONLY, 0o666) };

        let mut buf = [0u8; EXPECTED.len()];
        let ret = handler.execute((
            syscall::Sync,
            syscall::Read { fd, buf: &mut buf },
            syscall::Close { fd },
        ));

        if cfg!(not(miri)) {
            assert_eq!(ret, Ok((Ok(()), Some(Ok(EXPECTED.len())), Ok(()))));
            assert_eq!(buf, EXPECTED.as_bytes());
            assert_eq!(unsafe { libc::close(fd) }, -1);
            assert_eq!(unsafe { libc::__errno_location().read() }, EBADF);
        } else {
            assert_eq!(ret, Ok((Err(ENOSYS), Some(Err(ENOSYS)), Err(ENOSYS))));
        }
    });
}

#[test]
fn uname() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        let mut buf = unsafe { mem::zeroed() };
        if i % 2 == 0 {
            assert_eq!(handler.uname(&mut buf), Ok(()));
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [SYS_uname as _, &mut buf as *mut _ as _, 0, 0, 0, 0, 0],
                    )
                },
                Ok([0, 0])
            );
        }

        fn field(val: &str) -> [c_char; 65] {
            let mut buf = [0u8; 65];
            let val = val.as_bytes();
            buf[..val.len()].copy_from_slice(val);
            unsafe { transmute(buf) }
        }
        assert_eq!(buf, unsafe {
            transmute(utsname {
                sysname: field("Linux"),
                nodename: field("localhost.localdomain"),
                release: field("5.6.0"),
                version: field("#1"),
                machine: field("x86_64"),
                domainname: [0; 65],
            })
        });
    });
}

#[test]
#[serial]
fn write() {
    run_test(2, [0xff; 16], move |i, platform, handler| {
        const EXPECTED: &str = "write";
        let path = temp_dir().join("sallyport-test-write");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .create(true)
            .open(path)
            .unwrap();

        if i % 2 == 0 {
            assert_eq!(
                handler.write(file.as_raw_fd(), EXPECTED.as_bytes()),
                if cfg!(not(miri)) {
                    Ok(EXPECTED.len())
                } else {
                    Err(ENOSYS)
                }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_write as _,
                            file.as_raw_fd() as _,
                            EXPECTED.as_ptr() as _,
                            EXPECTED.len(),
                            0,
                            0,
                            0,
                        ],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([EXPECTED.len(), 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        if cfg!(not(miri)) {
            let mut got = String::new();
            file.rewind().unwrap();
            file.read_to_string(&mut got).unwrap();
            assert_eq!(got, EXPECTED);
        }
    })
}

#[test]
#[serial]
fn writev() {
    run_test(2, [0xff; 14], move |i, platform, handler| {
        const EXPECTED: &str = "01234567";
        const INPUT: &str = "012345678012345678";
        let path = temp_dir().join("sallyport-test-writev");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .create(true)
            .open(path)
            .unwrap();

        if i % 2 == 0 {
            assert_eq!(
                handler.writev(
                    file.as_raw_fd() as _,
                    &["", &INPUT[0..3], "", &INPUT[3..4], &INPUT[4..]]
                ),
                if cfg!(not(miri)) {
                    Ok(EXPECTED.len())
                } else {
                    Err(ENOSYS)
                }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall(
                        platform,
                        [
                            SYS_writev as _,
                            file.as_raw_fd() as _,
                            [
                                iovec {
                                    iov_base: INPUT.as_ptr() as _,
                                    iov_len: 0,
                                },
                                iovec {
                                    iov_base: INPUT[0..3].as_ptr() as _,
                                    iov_len: INPUT[0..3].len(),
                                },
                                iovec {
                                    iov_base: INPUT[3..].as_ptr() as _,
                                    iov_len: 0,
                                },
                                iovec {
                                    iov_base: INPUT[3..4].as_ptr() as _,
                                    iov_len: INPUT[3..4].len(),
                                },
                                iovec {
                                    iov_base: INPUT[4..].as_ptr() as _,
                                    iov_len: INPUT[4..].len(),
                                },
                            ]
                            .as_ptr() as _,
                            5,
                            0,
                            0,
                            0,
                        ],
                    )
                },
                if cfg!(not(miri)) {
                    Ok([EXPECTED.len(), 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        if cfg!(not(miri)) {
            let mut got = String::new();
            file.rewind().unwrap();
            file.read_to_string(&mut got).unwrap();
            assert_eq!(got, EXPECTED);
        }
    });
}
