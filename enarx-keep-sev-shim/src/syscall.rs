// SPDX-License-Identifier: Apache-2.0

use crate::arch::x86_64::{brk_user, mmap_user, NEXT_MMAP};
//use crate::arch::SyscallStack;
use crate::{eprintln, exit_hypervisor, print, HyperVisorExitCode};
//use vmbootspec::layout::USER_HEAP_OFFSET;
use nolibc::x86_64::error::Number as ErrNo;
use nolibc::x86_64::syscall::Number as SysCall;

trait NegAsUsize {
    fn neg_as_usize(self) -> usize;
}

impl NegAsUsize for ErrNo {
    fn neg_as_usize(self) -> usize {
        -Into::<i64>::into(self) as _
    }
}

extern "C" {
    fn _read_rsp() -> u64;
}

#[inline(always)]
pub fn read_rsp() -> u64 {
    unsafe { _read_rsp() }
}

extern "C" {
    fn _rdfsbase() -> u64;
    fn _wrfsbase(val: u64);
}

#[allow(clippy::many_single_char_names)]
#[inline(always)]
pub extern "C" fn handle_syscall(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    nr: usize,
) -> usize {
    #[cfg(debug_assertions)]
    eprintln!(
        "SC> raw: syscall({}, {:#X}, {:#X}, {:#X}, {}, {}, {:#X})",
        nr, a, b, c, d, e, f
    );

    //eprintln!("stackpointer: {:#X}", read_rsp());
    //eprintln!("stackpointer initial: {:#X}", f);

    match SysCall::from(nr as u64) {
        SysCall::EXIT => {
            eprintln!("SC> exit({})", a);
            exit_hypervisor(if a == 0 {
                HyperVisorExitCode::Success
            } else {
                HyperVisorExitCode::Failed
            });
            loop {}
        }
        SysCall::EXIT_GROUP => {
            eprintln!("SC> exit_group({})", a);
            exit_hypervisor(if a == 0 {
                HyperVisorExitCode::Success
            } else {
                HyperVisorExitCode::Failed
            });
            loop {}
        }
        SysCall::WRITE => {
            let fd = a;
            let data = b as *const u8;
            let len = c;
            match fd {
                1 | 2 => {
                    let cstr = unsafe { core::slice::from_raw_parts(data, len) };
                    match core::str::from_utf8(cstr) {
                        Ok(s) => {
                            eprintln!("SC> write({}, {:#?}) = {}", fd, s, len);
                            print!("{}", s);
                            len
                        }
                        Err(_) => {
                            eprintln!("SC> write({}, …) = -EINVAL", fd);
                            ErrNo::EINVAL.neg_as_usize()
                        }
                    }
                }
                _ => {
                    eprintln!("SC> write({}, \"…\") = -EBADFD", a);
                    ErrNo::EBADFD.neg_as_usize()
                }
            }
        }
        SysCall::WRITEV => {
            struct Iovec {
                iov_base: u64,  /* Starting address */
                iov_len: usize, /* Number of bytes to transfer */
            };
            let fd = a;
            let iov = b as *const Iovec;
            let iovcnt = c;
            let iovec = unsafe { core::slice::from_raw_parts(iov, iovcnt) };
            let mut written: usize = 0;
            match fd {
                1 | 2 => {
                    for iov in iovec {
                        let data = iov.iov_base as *const u8;
                        let len = iov.iov_len;
                        if len == 0 {
                            continue;
                        }
                        let cstr = unsafe { core::slice::from_raw_parts(data, len) };
                        match core::str::from_utf8(cstr) {
                            Ok(s) => {
                                eprintln!("SC> writev({}, {:#?}) = {}", fd, s, len);
                                print!("{}", s);
                                written += len;
                            }
                            Err(_) => {
                                eprintln!("SC> writev({}, …) = -EINVAL", fd);
                                return ErrNo::EINVAL.neg_as_usize();
                            }
                        }
                    }
                    written
                }
                _ => {
                    eprintln!("SC> write({}, \"…\") = -EBADFD", a);
                    ErrNo::EBADFD.neg_as_usize()
                }
            }
        }
        SysCall::ARCH_PRCTL => {
            const ARCH_SET_GS: usize = 0x1001;
            const ARCH_SET_FS: usize = 0x1002;
            const ARCH_GET_FS: usize = 0x1003;
            const ARCH_GET_GS: usize = 0x1004;

            match a {
                ARCH_SET_FS => {
                    eprintln!("SC> arch_prctl(ARCH_SET_FS, {:#X}) = 0", b);
                    let value: u64 = b as _;
                    unsafe {
                        _wrfsbase(value);
                    }
                    0
                }
                ARCH_GET_FS => unimplemented!(),
                ARCH_SET_GS => unimplemented!(),
                ARCH_GET_GS => unimplemented!(),
                x => {
                    eprintln!("SC> arch_prctl({:#X}, {:#X}) = -EINVAL", x, b);
                    ErrNo::EINVAL.neg_as_usize()
                }
            }
        }
        SysCall::MUNMAP => {
            let ret = 0;
            eprintln!("SC> dummy munmap({:#X}, {}, …) = {:#?}", a, b, ret);
            ret
        }
        SysCall::MMAP => {
            if a == 0 {
                let ret = mmap_user(b);
                eprintln!("SC> mmap({:#X}, {}, …) = {:#?}", a, b, ret);
                ret as _
            } else {
                eprintln!("SC> mmap({:#X}, {}, …)", a, b);
                todo!();
            }
        }
        SysCall::BRK => unsafe {
            match a {
                0 => {
                    eprintln!("SC> brk({:#X}) = {:#X}", a, NEXT_MMAP);
                    NEXT_MMAP as _
                }
                n => {
                    brk_user(n - NEXT_MMAP as usize);
                    eprintln!("SC> brk({:#X}) = {:#X}", a, NEXT_MMAP);
                    n as _
                }
            }
        },
        SysCall::MPROTECT => {
            let ret = 0;
            eprintln!("SC> mprotect({:#X}, {}, {}) = {:#?}", a, b, c, ret);
            ret as _
        }
        SysCall::UNAME => {
            eprintln!(
                r##"SC> uname({{sysname="Linux", nodename="enarx", release="5.4.8", version="1", machine="x86_64", domainname="(none)"}}) = 0"##
            );
            #[repr(C)]
            struct NewUtsname {
                sysname: [u8; 65],
                nodename: [u8; 65],
                release: [u8; 65],
                version: [u8; 65],
                machine: [u8; 65],
                domainname: [u8; 65],
            };
            let uts_ptr: *mut NewUtsname = a as _;
            unsafe {
                (*uts_ptr).sysname[..6].copy_from_slice(b"Linux\0");
                (*uts_ptr).nodename[..6].copy_from_slice(b"enarx\0");
                (*uts_ptr).release[..6].copy_from_slice(b"5.4.8\0");
                (*uts_ptr).version[..2].copy_from_slice(b"1\0");
                (*uts_ptr).machine[..7].copy_from_slice(b"x86_64\0");
                (*uts_ptr).domainname[..1].copy_from_slice(b"\0");
            }
            0
        }
        SysCall::READLINK => {
            let pathname = unsafe {
                let mut len = 0;
                let ptr: *const u8 = a as _;
                loop {
                    if ptr.offset(len).read() == 0 {
                        break;
                    }
                    len += 1;
                }
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(a as _, len as _))
            };

            if !pathname.eq("/proc/self/exe") {
                return ErrNo::ENOENT.neg_as_usize();
            }

            let outbuf = unsafe { core::slice::from_raw_parts_mut(b as _, c as _) };
            outbuf[..6].copy_from_slice(b"/init\0");
            eprintln!("SC> readlink({:#?}, \"/init\", {}) = 5", pathname, c);
            5
        }

        SysCall::RT_SIGACTION => {
            eprintln!("SC> rt_sigaction(…) = 0");
            0
        }
        SysCall::RT_SIGPROCMASK => {
            eprintln!("SC> rt_sigprocmask(…) = 0");
            0
        }
        SysCall::SIGALTSTACK => {
            eprintln!("SC> sigaltstack(…) = 0");
            0
        }
        SysCall::SET_TID_ADDRESS => {
            eprintln!("SC> set_tid_address(…) = 63618");
            63618
        }
        SysCall::IOCTL => match a {
            1 => {
                match b {
                    0x5413 /* TIOCGWINSZ */ => {
                        #[repr(C, packed)]
                        struct WinSize {
                            ws_row: u16,
                            ws_col: u16,
                            ws_xpixel: u16,
                            ws_ypixel: u16,
                        };
                        let p: *mut WinSize = c as _;
                        let winsize = WinSize {
                            ws_row: 40,
                            ws_col: 80,
                            ws_xpixel: 0,
                            ws_ypixel: 0
                        };
                        unsafe {
                            p.write_volatile(winsize);
                        }
                        eprintln!("SC> ioctl(1, TIOCGWINSZ, {{ws_row=40, ws_col=80, ws_xpixel=0, ws_ypixel=0}}) = 0");
                        0
                    },
                    _ => ErrNo::EINVAL.neg_as_usize(),
                }
            }
            _ => ErrNo::EINVAL.neg_as_usize(),
        },
        SysCall::FSTAT => match a {
            1 => {
                fn makedev(x: u64, y: u64) -> u64 {
                    (((x) & 0xffff_f000u64) << 32)
                        | (((x) & 0x0000_0fffu64) << 8)
                        | (((y) & 0xffff_ff00u64) << 12)
                        | ((y) & 0x0000_00ffu64)
                }

                #[repr(C)]
                #[derive(Debug, Copy, Clone)]
                pub struct timespec {
                    pub tv_sec: i64,
                    pub tv_nsec: i64,
                };

                #[repr(C)]
                #[derive(Debug, Copy, Clone)]
                pub struct Stat {
                    pub st_dev: u64,
                    pub st_ino: u64,
                    pub st_nlink: u64,
                    pub st_mode: u32,
                    pub st_uid: u32,
                    pub st_gid: u32,
                    pub __pad0: i32,
                    pub st_rdev: u64,
                    pub st_size: i64,
                    pub st_blksize: i64,
                    pub st_blocks: i64,
                    pub st_atime: timespec,
                    pub st_mtime: timespec,
                    pub st_ctime: timespec,
                    pub __glibc_reserved: [i64; 3usize],
                };

                let p: &mut Stat = &mut unsafe { *(c as *mut Stat) };
                p.st_dev = makedev(0, 0x17);
                p.st_ino = 3;
                p.st_mode = 0o020_000 | 0o620; // S_IFCHR
                p.st_nlink = 1;
                p.st_uid = 1000;
                p.st_gid = 5;
                p.st_blksize = 1024;
                p.st_blocks = 0;
                p.st_rdev = makedev(0x88, 0);
                p.st_atime.tv_sec=1_579_507_218 /* 2020-01-21T11:45:08.467721685+0100 */;
                p.st_atime.tv_nsec = 0;
                p.st_mtime.tv_sec=1_579_507_218 /* 2020-01-21T11:45:07.467721685+0100 */;
                p.st_mtime.tv_nsec = 0;
                p.st_ctime.tv_sec=1_579_507_218 /* 2020-01-20T09:00:18.467721685+0100 */;
                p.st_ctime.tv_nsec = 0;
                eprintln!("SC> fstat(1, {{st_dev=makedev(0, 0x17), st_ino=3, st_mode=S_IFCHR|0620, st_nlink=1, st_uid=1000, st_gid=5, st_blksize=1024, st_blocks=0, st_rdev=makedev(0x88, 0), st_atime=1579507218 /* 2020-01-21T11:45:08.467721685+0100 */, st_atime_nsec=0, st_mtime=1579507218 /* 2020-01-21T11:45:08.467721685+0100 */, st_mtime_nsec=0, st_ctime=1579507218 /* 2020-01-21T11:45:08.467721685+0100 */, st_ctime_nsec=0}}) = 0
 = 0");
                0
            }
            _ => ErrNo::EBADF.neg_as_usize(),
        },
        _ => {
            eprintln!("syscall({}, {}, {}, {}, {}, {}, {})", nr, a, b, c, d, e, f);
            //stack.dump();
            panic!("syscall {} not yet implemented", nr)
            // ENOSYS.neg_as_usize(),
        }
    }
}
