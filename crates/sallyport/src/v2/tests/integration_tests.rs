// SPDX-License-Identifier: Apache-2.0

use libc::{
    AF_INET, EBADF, EBADFD, ENOSYS, F_GETFD, F_GETFL, F_SETFD, F_SETFL, GRND_RANDOM, O_CREAT,
    O_RDONLY, O_RDWR, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO,
};
use std::env::temp_dir;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::mem::size_of;
use std::net::{TcpListener, TcpStream, UdpSocket};
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

    fn validate_mut<'b, T>(&self, ptr: usize) -> Result<&'b mut T> {
        Ok(unsafe { &mut *(ptr as *mut _) })
    }

    fn validate_slice_mut<'b, T>(&self, ptr: usize, len: usize) -> Result<&'b mut [T]> {
        Ok(unsafe { slice::from_raw_parts_mut(ptr as _, len) })
    }
}

fn run_test<const N: usize>(
    n: usize,
    mut block: [usize; N],
    f: impl Fn(usize, &mut Handler<TestPlatform<N>>),
) {
    let platform = TestPlatform(NonNull::from(&mut block));
    let mut handler = Handler::new(&mut block, platform);
    for i in 0..n {
        f(i, &mut handler);
    }
    let _ = block;
}

#[test]
#[serial]
fn close() {
    let path = temp_dir().join("sallyport-test-close");
    let c_path = CString::new(path.as_os_str().to_str().unwrap()).unwrap();

    run_test(2, [0xff; 16], move |i, handler| {
        // NOTE: `miri` only supports mode 0o666 at the time of writing
        // https://github.com/rust-lang/miri/blob/7a2f1cadcd5120c44eda3596053de767cd8173a2/src/shims/posix/fs.rs#L487-L493
        let fd = unsafe { libc::open(c_path.as_ptr(), O_RDWR | O_CREAT, 0o666) };

        if cfg!(feature = "asm") {
            if i % 2 == 0 {
                assert_eq!(handler.close(fd), Ok(()));
            } else {
                assert_eq!(
                    unsafe { handler.syscall([libc::SYS_close as _, fd as _, 0, 0, 0, 0, 0]) },
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
                    unsafe { handler.syscall([libc::SYS_close as _, fd as _, 0, 0, 0, 0, 0]) },
                    Err(ENOSYS)
                );
            }
        }
    })
}

#[test]
#[serial]
fn fcntl() {
    let file = File::create(temp_dir().join("sallyport-test-fcntl")).unwrap();
    let fd = file.as_raw_fd();

    run_test(2, [0xff; 16], move |i, handler| {
        for cmd in [F_GETFD] {
            if i % 2 == 0 {
                assert_eq!(
                    handler.fcntl(fd, cmd, 0),
                    if cfg!(feature = "asm") {
                        Ok(unsafe { libc::fcntl(fd, cmd) })
                    } else {
                        Err(ENOSYS)
                    }
                );
            } else {
                assert_eq!(
                    unsafe {
                        handler.syscall([libc::SYS_fcntl as _, fd as _, cmd as _, 0, 0, 0, 0])
                    },
                    if cfg!(feature = "asm") {
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
                    if cfg!(feature = "asm") {
                        Ok(unsafe { libc::fcntl(fd, cmd, arg) })
                    } else {
                        Err(ENOSYS)
                    }
                );
            } else {
                assert_eq!(
                    unsafe {
                        handler.syscall([
                            libc::SYS_fcntl as _,
                            fd as _,
                            cmd as _,
                            arg as _,
                            0,
                            0,
                            0,
                        ])
                    },
                    if cfg!(feature = "asm") {
                        Ok([unsafe { libc::fcntl(fd, cmd, arg) } as _, 0])
                    } else {
                        Err(ENOSYS)
                    }
                );
            }
        }
    });
    let _ = file;
}

#[test]
#[serial]
fn fstat() {
    let file = File::create(temp_dir().join("sallyport-test-fstat")).unwrap();
    let fd = file.as_raw_fd();

    run_test(2, [0xff; 16], move |_, handler| {
        let mut fd_stat = unsafe { mem::zeroed() };
        assert_eq!(handler.fstat(fd, &mut fd_stat), Err(EBADFD));
        assert_eq!(
            unsafe {
                handler.syscall([
                    libc::SYS_fstat as _,
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
                        libc::SYS_fstat as _,
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
                    libc::SYS_getrandom as _,
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
    const EXPECTED: &str = "read";
    let path = temp_dir().join("sallyport-test-read");
    write!(&mut File::create(&path).unwrap(), "{}", EXPECTED).unwrap();

    run_test(2, [0xff; 16], move |i, handler| {
        let mut buf = [0u8; EXPECTED.len()];

        let file = File::open(&path).unwrap();
        if i % 2 == 0 {
            assert_eq!(
                handler.read(file.as_raw_fd(), &mut buf),
                if cfg!(feature = "asm") {
                    Ok(EXPECTED.len())
                } else {
                    Err(ENOSYS)
                }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall([
                        libc::SYS_read as _,
                        file.as_raw_fd() as _,
                        buf.as_mut_ptr() as _,
                        EXPECTED.len(),
                        0,
                        0,
                        0,
                    ])
                },
                if cfg!(feature = "asm") {
                    Ok([EXPECTED.len(), 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        if cfg!(feature = "asm") {
            assert_eq!(buf, EXPECTED.as_bytes());
        }
    });
}

#[test]
#[cfg_attr(miri, ignore)]
fn recv() {
    const EXPECTED: &str = "recv";

    run_test(2, [0xff; 32], move |i, handler| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("couldn't bind to address");
        let addr = listener.local_addr().unwrap();

        let client = thread::spawn(move || {
            assert_eq!(
                TcpStream::connect(addr)
                    .expect("couldn't connect to address")
                    .write(EXPECTED.as_bytes())
                    .expect("couldn't write data"),
                EXPECTED.len()
            );
        });
        let stream = listener.accept().expect("couldn't accept connection").0;

        let mut buf = [0u8; EXPECTED.len()];
        if i % 2 == 0 {
            assert_eq!(
                handler.recv(stream.as_raw_fd(), &mut buf, 0,),
                if cfg!(feature = "asm") {
                    Ok(EXPECTED.len())
                } else {
                    Err(ENOSYS)
                }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall([
                        libc::SYS_recvfrom as _,
                        stream.as_raw_fd() as _,
                        buf.as_mut_ptr() as _,
                        EXPECTED.len(),
                        0,
                        0,
                        0,
                    ])
                },
                if cfg!(feature = "asm") {
                    Ok([EXPECTED.len(), 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        if cfg!(feature = "asm") {
            assert_eq!(buf, EXPECTED.as_bytes());
        }
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
        let mut src_addr: libc::sockaddr = unsafe { mem::zeroed() };
        let mut src_addr_bytes = unsafe {
            slice::from_raw_parts_mut(&mut src_addr as *mut _ as _, size_of::<libc::sockaddr>())
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
                if cfg!(feature = "asm") {
                    Ok(EXPECTED.len())
                } else {
                    Err(ENOSYS)
                }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall([
                        libc::SYS_recvfrom as _,
                        socket.as_raw_fd() as _,
                        buf.as_mut_ptr() as _,
                        EXPECTED.len(),
                        0,
                        src_addr_bytes.as_mut_ptr() as _,
                        &mut addrlen as *mut _ as _,
                    ])
                },
                if cfg!(feature = "asm") {
                    Ok([EXPECTED.len(), 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        if cfg!(feature = "asm") {
            assert_eq!(buf, EXPECTED.as_bytes());
            assert_eq!(
                src_addr,
                libc::sockaddr {
                    sa_family: AF_INET as _,
                    sa_data: [0xff as _, 0xfe as _, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
                },
            );
            assert_eq!(addrlen, size_of::<libc::sockaddr>() as _);
        }
        client.join().expect("couldn't join client thread");
    });
}

#[test]
#[serial]
fn sync_read_close() {
    const EXPECTED: &str = "sync-read-close";
    let path = temp_dir().join("sallyport-test-sync-read-close");
    write!(&mut File::create(&path).unwrap(), "{}", EXPECTED).unwrap();

    let c_path = CString::new(path.as_os_str().to_str().unwrap()).unwrap();
    run_test(1, [0xff; 64], move |_, handler| {
        let fd = unsafe { libc::open(c_path.as_ptr(), O_RDONLY, 0o666) };

        let mut buf = [0u8; EXPECTED.len()];
        let ret = handler.execute((
            syscall::Sync,
            syscall::Read { fd, buf: &mut buf },
            syscall::Close { fd },
        ));

        if cfg!(feature = "asm") {
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
    const EXPECTED: &str = "write";
    let path = temp_dir().join("sallyport-test-write");

    run_test(2, [0xff; 16], move |i, handler| {
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
                if cfg!(feature = "asm") {
                    Ok(EXPECTED.len())
                } else {
                    Err(ENOSYS)
                }
            );
        } else {
            assert_eq!(
                unsafe {
                    handler.syscall([
                        libc::SYS_write as _,
                        file.as_raw_fd() as _,
                        EXPECTED.as_ptr() as _,
                        EXPECTED.len(),
                        0,
                        0,
                        0,
                    ])
                },
                if cfg!(feature = "asm") {
                    Ok([EXPECTED.len(), 0])
                } else {
                    Err(ENOSYS)
                }
            );
        }
        if cfg!(feature = "asm") {
            let mut got = String::new();
            file.rewind().unwrap();
            file.read_to_string(&mut got).unwrap();
            assert_eq!(got, EXPECTED);
        }
    })
}
