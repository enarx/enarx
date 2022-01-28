// SPDX-License-Identifier: Apache-2.0

use libc::{
    c_int, sockaddr, SYS_accept, SYS_accept4, SYS_bind, SYS_close, SYS_fcntl, SYS_fstat,
    SYS_getrandom, SYS_getsockname, SYS_listen, SYS_read, SYS_recvfrom, SYS_setsockopt, SYS_socket,
    SYS_write, AF_INET, EBADF, EBADFD, ENOSYS, F_GETFD, F_GETFL, F_SETFD, F_SETFL, GRND_RANDOM,
    O_CREAT, O_RDONLY, O_RDWR, SOCK_CLOEXEC, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, STDERR_FILENO,
    STDIN_FILENO, STDOUT_FILENO,
};
use std::env::temp_dir;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::mem::size_of;
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::prelude::AsRawFd;
use std::ptr::NonNull;
use std::slice;
use std::{mem, thread};

use sallyport::guest::syscall::types::SockaddrOutput;
use sallyport::guest::{syscall, Execute, Handler, Platform};
use sallyport::item::Block;
use sallyport::{host, Result};
use serial_test::serial;

struct TestPlatform<const N: usize>(NonNull<[usize; N]>);

impl<const N: usize> Platform for TestPlatform<N> {
    fn sally(&mut self) -> Result<()> {
        host::execute(Block::from(unsafe { &mut self.0.as_mut()[..] }));
        Ok(())
    }

    fn validate<'b, T>(&self, ptr: usize) -> Result<&'b T> {
        Ok(unsafe { &*(ptr as *const _) })
    }

    fn validate_mut<'b, T>(&self, ptr: usize) -> Result<&'b mut T> {
        Ok(unsafe { &mut *(ptr as *mut _) })
    }

    fn validate_slice<'b, T>(&self, ptr: usize, len: usize) -> Result<&'b [T]> {
        Ok(unsafe { slice::from_raw_parts(ptr as _, len) })
    }

    fn validate_slice_mut<'b, T>(&self, ptr: usize, len: usize) -> Result<&'b mut [T]> {
        Ok(unsafe { slice::from_raw_parts_mut(ptr as _, len) })
    }

    fn validate_str<'b>(&self, ptr: usize) -> Result<&'b [u8]> {
        Ok(unsafe { CStr::from_ptr(ptr as _) }.to_bytes())
    }
}

fn run_test<const N: usize>(
    n: usize,
    block: [usize; N],
    f: impl FnOnce(usize, &mut Handler<TestPlatform<N>>) + Sync + Send + Copy + 'static,
) {
    for i in 0..n {
        thread::Builder::new()
            .name(format!("iteration {}", i))
            .spawn(move || {
                let mut block = block;
                let platform = TestPlatform(NonNull::from(&mut block));
                let mut tls = Default::default();
                let mut handler = Handler::new(&mut block, platform, &mut tls);
                f(i, &mut handler);
            })
            .expect(&format!("couldn't spawn test iteration {} thread", i))
            .join()
            .expect(&format!("couldn't join test iteration {} thread", i))
    }
}

fn syscall_socket(opaque: bool, exec: &mut impl Execute) -> c_int {
    let fd = if !opaque {
        exec.socket(AF_INET, SOCK_STREAM, 0)
            .expect("couldn't execute 'socket' syscall")
    } else {
        let [fd, ret1] =
            unsafe { exec.syscall([SYS_socket as _, AF_INET as _, SOCK_STREAM as _, 0, 0, 0, 0]) }
                .expect("couldn't execute 'socket' syscall");
        assert_eq!(ret1, 0);
        fd as _
    };
    assert!(fd >= 0);
    fd
}

fn syscall_recv(opaque: bool, exec: &mut impl Execute, fd: c_int, buf: &mut [u8]) {
    let expected_len = buf.len();
    if !opaque {
        assert_eq!(exec.recv(fd, buf, 0), Ok(expected_len));
    } else {
        assert_eq!(
            unsafe {
                exec.syscall([
                    SYS_recvfrom as _,
                    fd as _,
                    buf.as_mut_ptr() as _,
                    expected_len,
                    0,
                    0,
                    0,
                ])
            },
            Ok([expected_len, 0])
        );
    }
}

fn write_tcp(addr: impl ToSocketAddrs, buf: &[u8]) {
    assert_eq!(
        TcpStream::connect(addr)
            .expect("couldn't connect to address")
            .write(buf)
            .expect("couldn't write data"),
        buf.len()
    );
}

#[test]
#[serial]
fn close() {
    run_test(2, [0xff; 16], move |i, handler| {
        let path = temp_dir().join(format!("sallyport-test-close-{}", i));
        let c_path = CString::new(path.as_os_str().to_str().unwrap()).unwrap();

        // NOTE: `miri` only supports mode 0o666 at the time of writing
        // https://github.com/rust-lang/miri/blob/7a2f1cadcd5120c44eda3596053de767cd8173a2/src/shims/posix/fs.rs#L487-L493
        let fd = unsafe { libc::open(c_path.as_ptr(), O_RDWR | O_CREAT, 0o666) };
        if cfg!(not(miri)) {
            if i % 2 == 0 {
                assert_eq!(handler.close(fd), Ok(()));
            } else {
                assert_eq!(
                    unsafe { handler.syscall([SYS_close as _, fd as _, 0, 0, 0, 0, 0]) },
                    Ok([0, 0])
                );
            }
            assert_eq!(unsafe { libc::close(fd) }, -1);
            assert_eq!(unsafe { libc::__errno_location().read() }, EBADF);
        } else {
            if i % 2 == 0 {
                assert_eq!(handler.close(fd), Err(ENOSYS));
            } else {
                assert_eq!(
                    unsafe { handler.syscall([SYS_close as _, fd as _, 0, 0, 0, 0, 0]) },
                    Err(ENOSYS)
                );
            }
        }
    })
}

#[test]
#[serial]
fn fcntl() {
    run_test(2, [0xff; 16], move |i, handler| {
        let file = File::create(temp_dir().join(format!("sallyport-test-fcntl-{}", i))).unwrap();
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
                    unsafe { handler.syscall([SYS_fcntl as _, fd as _, cmd as _, 0, 0, 0, 0]) },
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
                        handler.syscall([SYS_fcntl as _, fd as _, cmd as _, arg as _, 0, 0, 0])
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

    run_test(1, [0xff; 16], move |_, handler| {
        let mut fd_stat = unsafe { mem::zeroed() };
        assert_eq!(handler.fstat(fd, &mut fd_stat), Err(EBADFD));
        assert_eq!(
            unsafe {
                handler.syscall([
                    SYS_fstat as _,
                    fd as _,
                    &mut fd_stat as *mut _ as _,
                    0,
                    0,
                    0,
                    0,
                ])
            },
            Err(EBADFD)
        );

        for fd in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] {
            let mut stat = unsafe { mem::zeroed() };
            assert_eq!(handler.fstat(fd, &mut stat), Ok(()));
            assert_eq!(
                unsafe {
                    handler.syscall([
                        SYS_fstat as _,
                        fd as _,
                        &mut stat as *mut _ as _,
                        0,
                        0,
                        0,
                        0,
                    ])
                },
                Ok([0, 0])
            );
        }
    });
    let _ = file;
}

#[test]
#[serial]
#[cfg_attr(miri, ignore)]
fn getrandom() {
    run_test(1, [0xff; 16], move |_, handler| {
        const LEN: usize = 64;

        let mut buf = [0u8; LEN];
        assert_eq!(handler.getrandom(&mut buf, GRND_RANDOM), Ok(LEN));
        assert_ne!(buf, [0u8; LEN]);

        let mut buf_2 = buf.clone();
        assert_eq!(
            unsafe {
                handler.syscall([
                    SYS_getrandom as _,
                    buf_2.as_mut_ptr() as _,
                    LEN,
                    GRND_RANDOM as _,
                    0,
                    0,
                    0,
                ])
            },
            Ok([LEN, 0])
        );
        assert_ne!(buf_2, [0u8; LEN]);
        assert_ne!(buf_2, buf);
    });
}

#[test]
#[serial]
fn read() {
    run_test(2, [0xff; 16], move |i, handler| {
        const EXPECTED: &str = "read";
        let path = temp_dir().join(format!("sallyport-test-read-{}", i));
        write!(&mut File::create(&path).unwrap(), "{}", EXPECTED).unwrap();

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
                    handler.syscall([
                        SYS_read as _,
                        file.as_raw_fd() as _,
                        buf.as_mut_ptr() as _,
                        EXPECTED.len(),
                        0,
                        0,
                        0,
                    ])
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
#[serial]
#[cfg_attr(miri, ignore)]
fn tcp_server() {
    run_test(4, [0xff; 32], move |i, handler| {
        let sockfd = syscall_socket(i % 2 != 0, handler);
        let optval = 1 as c_int;
        if i % 2 == 0 {
            assert_eq!(
                handler.setsockopt(sockfd, SOL_SOCKET as _, SO_REUSEADDR as _, Some(&optval)),
                Ok(0)
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall([
                        SYS_setsockopt as _,
                        sockfd as _,
                        SOL_SOCKET as _,
                        SO_REUSEADDR as _,
                        &optval as *const _ as _,
                        size_of::<c_int>(),
                        0,
                    ])
                },
                Ok([0, 0])
            );
        }

        let bind_addr = sockaddr {
            sa_family: AF_INET as _,
            sa_data: [0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        if i % 2 == 0 {
            assert_eq!(handler.bind(sockfd, &bind_addr), Ok(()));
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall([
                        SYS_bind as _,
                        sockfd as _,
                        &bind_addr as *const _ as _,
                        size_of::<sockaddr>(),
                        0,
                        0,
                        0,
                    ])
                },
                Ok([0, 0])
            );
        }
        assert_eq!(
            bind_addr,
            sockaddr {
                sa_family: AF_INET as _,
                sa_data: [0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );

        if i % 2 == 0 {
            assert_eq!(handler.listen(sockfd, 128), Ok(()));
        } else {
            assert_eq!(
                unsafe { handler.syscall([SYS_listen as _, sockfd as _, 128, 0, 0, 0, 0,]) },
                Ok([0, 0])
            );
        }

        let mut addr: sockaddr = unsafe { mem::zeroed() };
        let mut addrlen = size_of::<sockaddr>() as _;
        if i % 2 == 0 {
            assert_eq!(
                handler.getsockname(sockfd, (&mut addr, &mut addrlen)),
                Ok(())
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall([
                        SYS_getsockname as _,
                        sockfd as _,
                        &mut addr as *mut _ as _,
                        &mut addrlen as *mut _ as _,
                        0,
                        0,
                        0,
                    ])
                },
                Ok([0, 0])
            );
        }
        assert_eq!(addrlen, size_of::<sockaddr>() as _);
        assert_ne!(
            addr,
            sockaddr {
                sa_family: AF_INET as _,
                sa_data: [0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );
        let addr = addr;

        const EXPECTED: &str = "tcp";
        let client = thread::Builder::new()
            .name(String::from("client"))
            .spawn(move || {
                write_tcp(
                    (
                        "127.0.0.1",
                        u16::from_be_bytes([addr.sa_data[0] as _, addr.sa_data[1] as _]),
                    ),
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
                        .syscall([
                            SYS_accept4 as _,
                            sockfd as _,
                            &mut accept_addr as *mut _ as _,
                            &mut accept_addrlen as *mut _ as _,
                            SOCK_CLOEXEC as _,
                            0,
                            0,
                        ])
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
                        .syscall([
                            SYS_accept as _,
                            sockfd as _,
                            &mut accept_addr as *mut _ as _,
                            &mut accept_addrlen as *mut _ as _,
                            0,
                            0,
                            0,
                        ])
                        .expect("couldn't `accept` client connection")
                };
                assert_eq!(ret1, 0);
                sockfd as _
            }
        };
        assert!(accept_sockfd >= 0);

        let mut buf = [0u8; EXPECTED.len()];
        syscall_recv(i % 2 != 0, handler, accept_sockfd, &mut buf);
        assert_eq!(buf, EXPECTED.as_bytes());
        client.join().expect("couldn't join client thread");
    });
}

#[test]
#[serial]
#[cfg_attr(miri, ignore)]
fn recv() {
    const EXPECTED: &str = "recv";

    run_test(2, [0xff; 32], move |i, handler| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("couldn't bind to address");
        let addr = listener.local_addr().unwrap();

        let client = thread::spawn(move || {
            write_tcp(addr, EXPECTED.as_bytes());
        });
        let stream = listener.accept().expect("couldn't accept connection").0;

        let mut buf = [0u8; EXPECTED.len()];
        syscall_recv(i % 2 != 0, handler, stream.as_raw_fd(), &mut buf);
        assert_eq!(buf, EXPECTED.as_bytes());
        client.join().expect("couldn't join client thread");
    });
}

#[test]
#[serial]
#[cfg_attr(miri, ignore)]
fn recvfrom() {
    const EXPECTED: &str = "recvfrom";
    const SRC_ADDR: &str = "127.0.0.1:65534";

    run_test(2, [0xff; 32], move |i, handler| {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("couldn't bind to address");
        let addr = socket.local_addr().unwrap();

        let client = thread::spawn(move || {
            assert_eq!(
                UdpSocket::bind(SRC_ADDR)
                    .expect("couldn't bind to address")
                    .send_to(EXPECTED.as_bytes(), addr)
                    .expect("couldn't send data"),
                EXPECTED.len()
            );
        });

        let mut buf = [0u8; EXPECTED.len()];
        let mut src_addr: sockaddr = unsafe { mem::zeroed() };
        let mut src_addr_bytes = unsafe {
            slice::from_raw_parts_mut(&mut src_addr as *mut _ as _, size_of::<sockaddr>())
        };
        let mut addrlen = src_addr_bytes.len() as _;
        if i % 2 == 0 {
            assert_eq!(
                handler.recvfrom(
                    socket.as_raw_fd(),
                    &mut buf,
                    0,
                    SockaddrOutput::new(&mut src_addr_bytes, &mut addrlen),
                ),
                Ok(EXPECTED.len())
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall([
                        SYS_recvfrom as _,
                        socket.as_raw_fd() as _,
                        buf.as_mut_ptr() as _,
                        EXPECTED.len(),
                        0,
                        src_addr_bytes.as_mut_ptr() as _,
                        &mut addrlen as *mut _ as _,
                    ])
                },
                Ok([EXPECTED.len(), 0])
            );
        }
        assert_eq!(buf, EXPECTED.as_bytes());
        assert_eq!(
            src_addr,
            sockaddr {
                sa_family: AF_INET as _,
                sa_data: [0xff as _, 0xfe as _, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
            },
        );
        assert_eq!(addrlen, size_of::<sockaddr>() as _);
        client.join().expect("couldn't join client thread");
    });
}

#[test]
#[serial]
fn sync_read_close() {
    run_test(1, [0xff; 64], move |_, handler| {
        const EXPECTED: &str = "sync-read-close";
        let path = temp_dir().join("sallyport-test-sync-read-close");
        write!(&mut File::create(&path).unwrap(), "{}", EXPECTED).unwrap();

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
#[serial]
fn write() {
    run_test(2, [0xff; 16], move |i, handler| {
        const EXPECTED: &str = "write";
        let path = temp_dir().join("sallyport-test-write");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .create(true)
            .open(&path)
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
                    handler.syscall([
                        SYS_write as _,
                        file.as_raw_fd() as _,
                        EXPECTED.as_ptr() as _,
                        EXPECTED.len(),
                        0,
                        0,
                        0,
                    ])
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
