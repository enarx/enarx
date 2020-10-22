// SPDX-License-Identifier: Apache-2.0

//! syscall interface layer between assembler and rust

use crate::addr::{HostVirtAddr, ShimPhysUnencryptedAddr};
use crate::eprintln;
use crate::frame_allocator::FRAME_ALLOCATOR;
use crate::hostcall::{self, shim_write_all, HostFd, HOST_CALL};
use crate::paging::SHIM_PAGETABLE;
use crate::payload::{NEXT_BRK_RWLOCK, NEXT_MMAP_RWLOCK};
use core::convert::TryFrom;
use core::mem::{size_of, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use primordial::{Address, Register};
use sallyport::request;
use x86_64::registers::wrfsbase;
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::{align_up, VirtAddr};

const FAKE_UID: usize = 1000;
const FAKE_GID: usize = 1000;

/// syscall service routine
///
/// # Safety
///
/// This function is not be called from rust.
#[inline(never)]
#[naked]
pub unsafe fn _syscall_enter() -> ! {
    use crate::gdt::{USER_CODE_SEGMENT, USER_DATA_SEGMENT};
    // TaskStateSegment.privilege_stack_table[0]
    const KERNEL_RSP_OFF: usize = size_of::<u32>();
    // TaskStateSegment.privilege_stack_table[3]
    const USR_RSP_OFF: usize = size_of::<u32>() + 3 * size_of::<u64>();

    asm!("
    # prepare the stack for iretq and load the kernel rsp
    swapgs                                            # set gs segment to TSS
    mov    QWORD PTR gs:{0},        rsp               # save userspace rsp
    mov    rsp,                     QWORD PTR gs:{1}  # load kernel rsp
    push   {2}
    push   QWORD PTR gs:{0}                           # push userspace rsp - stack_pointer_ring_3
    mov    QWORD PTR gs:{0},        0x0               # clear userspace rsp in the TSS
    push   r11                                        # push RFLAGS stored in r11
    push   {3}
    push   rcx                                        # push userspace return pointer

    # Arguments in registers:
    # SYSV:    rdi, rsi, rdx, rcx, r8, r9
    # SYSCALL: rdi, rsi, rdx, r10, r8, r9 and syscall number in rax
    mov    rcx,                     r10

    # save registers
    push   rdi
    push   rsi
    push   rdx
    push   rcx
    push   r11
    push   r10
    push   r8
    push   r9

    # syscall number on the stack as the seventh argument
    push   rax

    call   {4}

    # skip %rax pop, as it is the return value
    add    rsp,                     0x8

    # restore registers
    pop    r9
    pop    r8
    pop    r10
    pop    r11
    pop    rcx
    pop    rdx
    pop    rsi
    pop    rdi

    swapgs                                            # restore gs

    iretq
    ",
    const USR_RSP_OFF,
    const KERNEL_RSP_OFF,
    const USER_DATA_SEGMENT,
    const USER_CODE_SEGMENT,
    sym syscall_rust,
    options(noreturn)
    );
}

#[allow(clippy::many_single_char_names)]
#[no_mangle]
/// Handle a syscall in rust
pub extern "C" fn syscall_rust(
    a: Register<usize>,
    b: Register<usize>,
    c: Register<usize>,
    d: Register<usize>,
    e: Register<usize>,
    f: Register<usize>,
    nr: usize,
) -> usize {
    /*
    #[cfg(debug_assertions)]
    eprintln!(
        "SC> raw: syscall({}, {:#x}, {:#x}, {:#x}, {}, {}, {:#x})",
        nr,
        usize::from(a),
        usize::from(b),
        usize::from(c),
        usize::from(d),
        usize::from(e),
        usize::from(f)
    );
    */
    let do_syscall = || -> Result<usize, libc::c_int> {
        match nr as _ {
            libc::SYS_exit => exit(usize::from(a) as _),
            libc::SYS_exit_group => exit_group(usize::from(a) as _),
            libc::SYS_read => read(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_readv => unsafe { readv(usize::from(a) as _, b.into(), usize::from(c) as _) },
            libc::SYS_write => unsafe { write(usize::from(a) as _, b.into(), c.into()) },
            libc::SYS_writev => unsafe {
                writev(usize::from(a) as _, b.into(), usize::from(c) as _)
            },
            libc::SYS_mmap => mmap(
                a.into(),
                b.into(),
                usize::from(c) as _,
                usize::from(d) as _,
                usize::from(e) as _,
                f.into(),
            ),
            libc::SYS_munmap => munmap(a.into(), b.into()),
            libc::SYS_arch_prctl => arch_prctl(usize::from(a) as _, b.into()),
            libc::SYS_set_tid_address => set_tid_address(a.into()),
            libc::SYS_rt_sigaction => rt_sigaction(usize::from(a) as _, b.into(), c.into()),
            libc::SYS_rt_sigprocmask => {
                rt_sigprocmask(usize::from(a) as _, b.into(), c.into(), d.into())
            }
            libc::SYS_sigaltstack => sigaltstack(a.into(), b.into()),
            libc::SYS_getrandom => unsafe { getrandom(a.into(), b.into(), usize::from(c) as _) },
            libc::SYS_brk => brk(a.into()),
            libc::SYS_ioctl => ioctl(usize::from(a) as _, b.into()),
            libc::SYS_mprotect => mprotect(a.into(), b.into(), usize::from(c) as _),
            libc::SYS_clock_gettime => clock_gettime(usize::from(a) as _, b.into()),
            libc::SYS_uname => unsafe { uname(a.into()) },
            libc::SYS_readlink => readlink(a.into(), b.into(), c.into()),
            libc::SYS_fstat => unsafe { fstat(usize::from(a) as _, b.into()) },
            libc::SYS_fcntl => fcntl(usize::from(a) as _, usize::from(b) as _),
            libc::SYS_madvise => madvise(a.into(), b.into(), usize::from(c) as _),
            libc::SYS_poll => unsafe { poll(a.into(), b.into(), usize::from(c) as _) },
            libc::SYS_getuid => getuid(),
            libc::SYS_getgid => getgid(),
            libc::SYS_geteuid => geteuid(),
            libc::SYS_getegid => getegid(),

            syscall => {
                //panic!("SC> unsupported syscall: {}", syscall);
                eprintln!("SC> unsupported syscall: {}", syscall);
                Err(libc::ENOSYS)
            }
        }
    };

    let res = do_syscall().unwrap_or_else(|e| e.checked_neg().unwrap() as usize) as usize;

    #[cfg(debug_assertions)]
    eprintln!("SC> = {:#x}", res);
    res
}

/// syscall
pub fn exit(status: libc::c_int) -> ! {
    eprintln!("SC> exit({})", status);
    hostcall::shim_exit(status);
}

/// syscall
pub fn exit_group(status: libc::c_int) -> ! {
    eprintln!("SC> exit_group({})", status);
    hostcall::shim_exit(status);
}

fn _read(fd: libc::c_int, trusted: *mut u8, trusted_len: usize) -> Result<usize, libc::c_int> {
    let mut host_call = HOST_CALL.try_lock().ok_or(libc::EIO)?;

    let block = host_call.as_mut_block();

    let c = block.cursor();
    let (_, buf) = unsafe { c.alloc::<u8>(trusted_len).or(Err(libc::EMSGSIZE))? };

    let buf_address = Address::from(buf.as_ptr());
    let phys_unencrypted = ShimPhysUnencryptedAddr::try_from(buf_address).unwrap();
    let host_virt: HostVirtAddr<_> = phys_unencrypted.into();

    block.msg.req = request!(libc::SYS_read => fd, host_virt, trusted_len);
    let result = unsafe { host_call.hostcall() };
    let result_len: usize = result.map(|r| r[0].into())?;

    if trusted_len < result_len {
        panic!("syscall read buffer overflow");
    }

    let block = host_call.as_mut_block();
    let c = block.cursor();
    unsafe { c.copy_into_raw_parts(trusted_len, trusted, result_len) }.or(Err(libc::EFAULT))?;

    Ok(result_len)
}

/// syscall
pub fn read(fd: libc::c_int, buf: *mut u8, count: libc::size_t) -> Result<usize, libc::c_int> {
    _read(fd, buf, count)
}

/// syscall
///
/// # Safety
/// Unsafe, because it dereferences `iov`.
pub unsafe fn readv(
    fd: libc::c_int,
    iov: *const libc::iovec,
    iovcnt: libc::c_int,
) -> Result<usize, libc::c_int> {
    // FIXME: unsafe
    let iovec = core::slice::from_raw_parts(iov, iovcnt as _);

    // FIXME: this is not an ideal implementation of readv, but for the sake
    // of simplicity this readv implementation behaves very much like how the
    // Linux kernel would for a module that does not support readv, but does
    // support read.
    let mut read = 0usize;
    for vec in iovec {
        let r = _read(fd, vec.iov_base as _, vec.iov_len as _)?;
        read = read.checked_add(r).unwrap();
    }

    Ok(read)
}

/// syscall
///
/// # Safety
/// The caller has to ensure `buf` points to valid memory.
pub unsafe fn write(
    fd: libc::c_int,
    buf: *const u8,
    count: libc::size_t,
) -> Result<usize, libc::c_int> {
    let mut host_call = HOST_CALL.try_lock().ok_or(libc::EIO)?;
    let slice = core::slice::from_raw_parts(buf, count);
    // FIXME: allocate unencrypted pages
    host_call.write(fd, slice).map(|r| r[0].into())
}

/// syscall
///
/// # Safety
/// The caller has to ensure `iov` and its contents points to valid memory.
pub unsafe fn writev(
    fd: libc::c_int,
    iov: *const libc::iovec,
    iovcnt: libc::c_int,
) -> Result<usize, libc::c_int> {
    let fd = HostFd::from_raw_fd(fd);
    let iovec = core::slice::from_raw_parts(iov, iovcnt as _);

    let bufsize = iovec
        .iter()
        .fold(0, |a: usize, e| a.checked_add(e.iov_len).unwrap());

    for vec in iovec {
        let data = core::slice::from_raw_parts(vec.iov_base as *const u8, vec.iov_len as usize);
        // FIXME: allocate unencrypted pages
        shim_write_all(fd, data)?;
    }
    Ok(bufsize)
}

/// syscall
pub fn arch_prctl(code: libc::c_int, addr: libc::c_ulong) -> Result<usize, libc::c_int> {
    const ARCH_SET_GS: libc::c_int = 0x1001;
    const ARCH_SET_FS: libc::c_int = 0x1002;
    const ARCH_GET_FS: libc::c_int = 0x1003;
    const ARCH_GET_GS: libc::c_int = 0x1004;

    match code {
        ARCH_SET_FS => {
            unsafe {
                wrfsbase(addr);
            }
            eprintln!("SC> arch_prctl(ARCH_SET_FS, {:#x}) = 0", addr);
            Ok(0)
        }
        ARCH_GET_FS => unimplemented!(),
        ARCH_SET_GS => unimplemented!(),
        ARCH_GET_GS => unimplemented!(),
        x => {
            eprintln!("SC> arch_prctl({:#x}, {:#x}) = -EINVAL", x, addr);
            Err(libc::EINVAL)
        }
    }
}

/// syscall
pub fn mprotect(
    addr: *const u8,
    len: libc::size_t,
    prot: libc::c_int,
) -> Result<usize, libc::c_int> {
    use x86_64::structures::paging::mapper::Mapper;

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

    if prot & libc::PROT_WRITE != 0 {
        flags |= PageTableFlags::WRITABLE;
    }

    if prot & libc::PROT_EXEC == 0 {
        flags |= PageTableFlags::NO_EXECUTE;
    }

    let mut page_table = SHIM_PAGETABLE.write();

    let start_addr = VirtAddr::from_ptr(addr);
    let start_page: Page = Page::containing_address(start_addr);
    let end_page: Page = Page::containing_address(start_addr + len - 1u64);
    let page_range = Page::range_inclusive(start_page, end_page);
    for page in page_range {
        unsafe {
            match page_table.update_flags(page, flags) {
                Ok(flush) => flush.flush(),
                Err(e) => {
                    eprintln!(
                        "SC> mprotect({:#?}, {}, {}, …) = EINVAL ({:#?})",
                        addr, len, prot, e
                    );
                    return Err(libc::EINVAL);
                }
            }
        }
    }
    eprintln!("SC> mprotect({:#?}, {}, {}, …) = 0", addr, len, prot);

    Ok(0)
}

/// syscall
pub fn mmap(
    addr: *const u8,
    length: libc::size_t,
    prot: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off_t,
) -> Result<usize, libc::c_int> {
    const PA: i32 = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

    match (addr as u64, length, prot, flags, fd, offset) {
        (0, _, _, PA, -1, 0) => {
            let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

            if prot & libc::PROT_WRITE != 0 {
                flags |= PageTableFlags::WRITABLE;
            }

            if prot & libc::PROT_EXEC == 0 {
                flags |= PageTableFlags::NO_EXECUTE;
            }

            let virt_addr = *NEXT_MMAP_RWLOCK.read().deref();
            let len_aligned = align_up(length as _, Page::<Size4KiB>::SIZE) as _;

            let mem_slice = FRAME_ALLOCATOR
                .write()
                .allocate_and_map_memory(
                    SHIM_PAGETABLE.write().deref_mut(),
                    virt_addr,
                    len_aligned,
                    flags,
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::USER_ACCESSIBLE,
                )
                .map_err(|_| {
                    eprintln!("SC> mmap({:#?}, {}, …) = ENOMEM", addr, length);
                    libc::ENOMEM
                })?;
            eprintln!(
                "SC> mmap({:#?}, {}, …) = {:#?}",
                addr,
                length,
                mem_slice.as_ptr()
            );
            unsafe {
                core::ptr::write_bytes(mem_slice.as_mut_ptr(), 0, length);
            }
            *NEXT_MMAP_RWLOCK.write().deref_mut() = virt_addr + (len_aligned as u64);

            //eprintln!("next_mmap = {:#x}", *NEXT_MMAP_RWLOCK::read().deref());

            Ok(mem_slice.as_ptr() as usize)
        }
        _ => {
            eprintln!("SC> mmap({:#?}, {}, …)", addr, length);
            unimplemented!()
        }
    }
}

/// syscall
pub fn brk(addr: *const u8) -> Result<usize, libc::c_int> {
    let len;

    let next_brk = *NEXT_BRK_RWLOCK.read().deref();
    let virt_addr = next_brk;

    match addr as usize {
        0 => {
            eprintln!("SC> brk({:#?}) = {:#x}", addr, next_brk.as_u64());
            Ok(next_brk.as_u64() as _)
        }
        n => {
            if n <= next_brk.as_u64() as usize {
                if n > (next_brk
                    .as_u64()
                    .checked_sub(Page::<Size4KiB>::SIZE)
                    .unwrap() as usize)
                {
                    // already mapped
                    eprintln!("SC> brk({:#?}) = {:#x}", addr, n);
                    return Ok(n);
                }

                // n most likely wrong
                return Err(libc::EINVAL);
            }

            len = n.checked_sub(next_brk.as_u64() as usize).unwrap();
            let len_aligned = align_up(len as _, Page::<Size4KiB>::SIZE) as _;
            let _ = FRAME_ALLOCATOR
                .write()
                .allocate_and_map_memory(
                    SHIM_PAGETABLE.write().deref_mut(),
                    virt_addr,
                    len_aligned,
                    PageTableFlags::PRESENT
                        | PageTableFlags::USER_ACCESSIBLE
                        | PageTableFlags::WRITABLE,
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::USER_ACCESSIBLE,
                )
                .map_err(|_| {
                    eprintln!("SC> brk({:#?}) = ENOMEM", addr);
                    libc::ENOMEM
                })?;

            *NEXT_BRK_RWLOCK.write() = virt_addr + (len_aligned as u64);

            eprintln!("SC> brk({:#?}) = {:#x}", addr, n);

            Ok(n)
        }
    }
}

/// Do a ioctl() syscall
///
pub fn ioctl(fd: libc::c_int, request: libc::c_ulong) -> Result<usize, libc::c_int> {
    match (fd as _, request as _) {
        (libc::STDIN_FILENO, libc::TIOCGWINSZ)
        | (libc::STDOUT_FILENO, libc::TIOCGWINSZ)
        | (libc::STDERR_FILENO, libc::TIOCGWINSZ) => {
            // the keep has no tty
            eprintln!("SC> ioctl({}, TIOCGWINSZ, … = -ENOTTY", fd);
            Err(libc::ENOTTY)
        }
        (libc::STDIN_FILENO, _) | (libc::STDOUT_FILENO, _) | (libc::STDERR_FILENO, _) => {
            eprintln!("SC> ioctl({}, {}), … = -EINVAL", fd, request);
            Err(libc::EINVAL)
        }
        _ => {
            eprintln!("SC> ioctl({}, {}), … = -EBADFD", fd, request);
            Err(libc::EBADFD)
        }
    }
}
/// Do a set_tid_address() syscall
///
/// This is currently unimplemented and returns a dummy thread id.
pub fn set_tid_address(_tidptr: *mut libc::c_int) -> Result<usize, libc::c_int> {
    // FIXME
    eprintln!("SC> set_tid_address(…) = 1");
    Ok(1)
}

/// Do a rt_sigaction() syscall
///
/// This is currently unimplemented and returns success.
pub fn rt_sigaction(
    _signum: libc::c_int,
    _act: *const libc::sigaction,
    _oldact: *mut libc::sigaction,
) -> Result<usize, libc::c_int> {
    // FIXME
    eprintln!("SC> rt_sigaction(…) = 0");
    Ok(0)
}

/// Do a rt_sigprocmask() syscall
///
/// This is currently unimplemented and returns success.
pub fn rt_sigprocmask(
    _how: libc::c_int,
    _set: *const libc::c_void,
    _oldset: *mut libc::c_void,
    _sigsetsize: libc::size_t,
) -> Result<usize, libc::c_int> {
    // FIXME
    eprintln!("SC> rt_sigprocmask(…) = 0");
    Ok(0)
}

/// Do a munmap() syscall
///
/// This is currently unimplemented and returns success.
pub fn munmap(_addr: *const libc::c_void, _lenght: libc::size_t) -> Result<usize, libc::c_int> {
    // FIXME
    eprintln!("SC> munmap(…) = 0");
    Ok(0)
}

/// Do a sigaltstack() syscall
///
/// This is currently unimplemented and returns success.
pub fn sigaltstack(
    _ss: *const libc::stack_t,
    _old_ss: *mut libc::stack_t,
) -> Result<usize, libc::c_int> {
    // FIXME
    eprintln!("SC> sigaltstack(…) = 0");
    Ok(0)
}

/// Do a getrandom() syscall
///
/// # Safety
/// The caller has to ensure `buf` points to valid memory
pub unsafe fn getrandom(
    buf: *mut u8,
    buflen: libc::size_t,
    flags: libc::c_uint,
) -> Result<usize, libc::c_int> {
    let flags = flags & !(libc::GRND_NONBLOCK | libc::GRND_RANDOM);

    if flags != 0 {
        return Err(libc::EINVAL);
    }

    let trusted = core::slice::from_raw_parts_mut(buf, buflen);

    for (i, chunk) in trusted.chunks_mut(8).enumerate() {
        let mut el = 0u64;
        loop {
            if core::arch::x86_64::_rdrand64_step(&mut el) == 1 {
                chunk.copy_from_slice(&el.to_ne_bytes()[..chunk.len()]);
                break;
            } else {
                if (flags & libc::GRND_NONBLOCK) != 0 {
                    eprintln!("SC> getrandom(…) = -EAGAIN");
                    return Err(libc::EAGAIN);
                }
                if (flags & libc::GRND_RANDOM) != 0 {
                    eprintln!("SC> getrandom(…) = {}", i.checked_mul(8).unwrap());
                    return Ok(i.checked_mul(8).unwrap());
                }
            }
        }
    }
    eprintln!("SC> getrandom(…) = {}", trusted.len());

    Ok(trusted.len())
}

/// syscall
pub fn clock_gettime(
    clockid: libc::clockid_t,
    tp: *mut libc::timespec,
) -> Result<usize, libc::c_int> {
    // FIXME: check `trusted`, if in payload space
    // https://github.com/enarx/enarx-keepldr/issues/78
    let trusted = NonNull::new(tp).ok_or(libc::EFAULT)?;

    let mut host_call = HOST_CALL.try_lock().ok_or(libc::EIO)?;

    let block = host_call.as_mut_block();

    let c = block.cursor();
    let (_, buf) = unsafe { c.alloc::<libc::timespec>(1).or(Err(libc::EMSGSIZE))? };

    let buf_address = Address::from(buf.as_ptr());
    let phys_unencrypted = ShimPhysUnencryptedAddr::try_from(buf_address).unwrap();
    let host_virt: HostVirtAddr<_> = phys_unencrypted.into();

    block.msg.req = request!(libc::SYS_clock_gettime => clockid, host_virt);
    let result = unsafe { host_call.hostcall() }.map(|r| r[0].into())?;

    let block = host_call.as_mut_block();
    let c = block.cursor();
    unsafe { c.copy_into(trusted) }.or(Err(libc::EMSGSIZE))?;

    Ok(result)
}

/// syscall
///
/// # Safety
/// The caller has to ensure `buf` points to valid memory.
pub unsafe fn uname(buf: *mut libc::utsname) -> Result<usize, libc::c_int> {
    // Faked, because we cannot promise any features provided by Linux in the future.
    eprintln!(
        r##"SC> uname({{sysname="Linux", nodename="enarx", release="5.4.8", version="1", machine="x86_64", domainname="(none)"}}) = 0"##
    );

    let mut uts = MaybeUninit::<libc::utsname>::zeroed().assume_init();
    uts.sysname[..5].copy_from_slice(TrySigned::try_signed(b"Linux").unwrap());
    uts.nodename[..5].copy_from_slice(TrySigned::try_signed(b"enarx").unwrap());
    uts.release[..5].copy_from_slice(TrySigned::try_signed(b"5.4.8").unwrap());
    uts.version[..6].copy_from_slice(TrySigned::try_signed(b"#1 SMP").unwrap());
    uts.machine[..6].copy_from_slice(TrySigned::try_signed(b"x86_64").unwrap());
    buf.write(uts);
    Ok(0)
}

/// syscall
pub fn readlink(
    pathname: *const libc::c_char,
    buf: *mut libc::c_char,
    bufsize: libc::size_t,
) -> Result<usize, libc::c_int> {
    // Fake readlink("/proc/self/exe")
    const PROC_SELF_EXE: &str = "/proc/self/exe";

    let pathname = unsafe {
        let mut len: isize = 0;
        let ptr: *const u8 = pathname as _;
        loop {
            if ptr.offset(len).read() == 0 {
                break;
            }
            len = len.checked_add(1).unwrap();
            if len as usize >= PROC_SELF_EXE.len() {
                break;
            }
        }
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(pathname as _, len as _))
    };

    if !pathname.eq(PROC_SELF_EXE) {
        return Err(libc::ENOENT);
    }

    let outbuf = unsafe { core::slice::from_raw_parts_mut(buf as _, bufsize as _) };
    outbuf[..6].copy_from_slice(b"/init\0");
    eprintln!("SC> readlink({:#?}, \"/init\", {}) = 5", pathname, bufsize);
    Ok(5)
}

/// syscall
///
/// # Safety
/// The caller has to ensure `statbuf` points to valid memory
pub unsafe fn fstat(fd: libc::c_int, statbuf: *mut libc::stat) -> Result<usize, libc::c_int> {
    // Fake fstat(0|1|2, ...) done by glibc or rust
    match fd {
        libc::STDIN_FILENO | libc::STDOUT_FILENO | libc::STDERR_FILENO => {
            #[allow(clippy::integer_arithmetic)]
            const fn makedev(x: u64, y: u64) -> u64 {
                (((x) & 0xffff_f000u64) << 32)
                    | (((x) & 0x0000_0fffu64) << 8)
                    | (((y) & 0xffff_ff00u64) << 12)
                    | ((y) & 0x0000_00ffu64)
            }

            let mut p = MaybeUninit::<libc::stat>::zeroed().assume_init();

            p.st_dev = makedev(
                0,
                match fd {
                    0 => 0x19,
                    _ => 0xc,
                },
            );
            p.st_ino = 3;
            p.st_mode = libc::S_IFIFO | 0o600;
            p.st_nlink = 1;
            p.st_uid = 1000;
            p.st_gid = 5;
            p.st_blksize = 4096;
            p.st_blocks = 0;
            p.st_rdev = makedev(0x88, 0);
            p.st_size = 0;

            p.st_atime = 1_579_507_218 /* 2020-01-21T11:45:08.467721685+0100 */;
            p.st_atime_nsec = 0;
            p.st_mtime = 1_579_507_218 /* 2020-01-21T11:45:07.467721685+0100 */;
            p.st_mtime_nsec = 0;
            p.st_ctime = 1_579_507_218 /* 2020-01-20T09:00:18.467721685+0100 */;
            p.st_ctime_nsec = 0;

            statbuf.write(p);

            eprintln!("SC> fstat({}, {{st_dev=makedev(0, 0x19), st_ino=3, st_mode=S_IFIFO|0600,\
                 st_nlink=1, st_uid=1000, st_gid=5, st_blksize=4096, st_blocks=0, st_size=0,\
                  st_rdev=makedev(0x88, 0), st_atime=1579507218 /* 2020-01-21T11:45:08.467721685+0100 */,\
                   st_atime_nsec=0, st_mtime=1579507218 /* 2020-01-21T11:45:08.467721685+0100 */,\
                    st_mtime_nsec=0, st_ctime=1579507218 /* 2020-01-21T11:45:08.467721685+0100 */,\
                     st_ctime_nsec=0}}) = 0", fd);
            Ok(0)
        }
        _ => Err(libc::EBADF),
    }
}

/// syscall
pub fn fcntl(fd: libc::c_int, cmd: libc::c_int) -> Result<usize, libc::c_int> {
    match (fd, cmd) {
        (libc::STDIN_FILENO, libc::F_GETFL) => {
            eprintln!("SC> fcntl({}, F_GETFD) = 0x402 (flags O_RDWR|O_APPEND)", fd);
            Ok((libc::O_RDWR | libc::O_APPEND) as _)
        }
        (libc::STDOUT_FILENO, libc::F_GETFL) | (libc::STDERR_FILENO, libc::F_GETFL) => {
            eprintln!("SC> fcntl({}, F_GETFD) = 0x1 (flags O_WRONLY)", fd);
            Ok(libc::O_WRONLY as _)
        }
        (libc::STDIN_FILENO, _) | (libc::STDOUT_FILENO, _) | (libc::STDERR_FILENO, _) => {
            eprintln!("SC> fcntl({}, {}) = -EINVAL", fd, cmd);
            Err(libc::EINVAL)
        }
        (_, _) => {
            eprintln!("SC> fcntl({}, {}) = -EBADFD", fd, cmd);
            Err(libc::EBADFD)
        }
    }
}

/// syscall
pub fn madvise(
    addr: *const libc::c_void,
    length: libc::size_t,
    advice: libc::c_int,
) -> Result<usize, libc::c_int> {
    eprintln!("SC> madvise(0x{:?}, {}, {}) = 0", addr, length, advice);

    Ok(0)
}

/// syscall
///
/// # Safety
/// The caller has to ensure `fds` points to valid memory.
pub unsafe fn poll(
    fds: *mut libc::pollfd,
    nfds: libc::nfds_t,
    timeout: libc::c_int,
) -> Result<usize, libc::c_int> {
    eprintln!("SC> poll(…) =  …");

    let mut host_call = HOST_CALL.try_lock().ok_or(libc::EIO)?;

    let block = host_call.as_mut_block();

    let c = block.cursor();

    let (_, buf) = c
        .copy_from_raw_parts(fds, nfds as _)
        .or(Err(libc::EMSGSIZE))?;

    let buf_address = Address::from(buf);
    let phys_unencrypted = ShimPhysUnencryptedAddr::try_from(buf_address).unwrap();
    let host_virt: HostVirtAddr<_> = phys_unencrypted.into();

    block.msg.req = request!(libc::SYS_poll => host_virt, nfds, timeout);
    let result = host_call.hostcall().map(|r| r[0].into())?;

    let block = host_call.as_mut_block();
    let c = block.cursor();

    c.copy_into_raw_parts(nfds as _, fds, nfds as _)
        .or(Err(libc::EMSGSIZE))?;

    Ok(result)
}

/// syscall
pub fn getuid() -> Result<usize, libc::c_int> {
    eprintln!("SC> getuid() = {}", FAKE_UID);
    Ok(FAKE_UID)
}

/// syscall
pub fn getgid() -> Result<usize, libc::c_int> {
    eprintln!("SC> getgid() = {}", FAKE_GID);
    Ok(FAKE_GID)
}

/// syscall
pub fn geteuid() -> Result<usize, libc::c_int> {
    eprintln!("SC> geteuid() = {}", FAKE_UID);
    Ok(FAKE_UID)
}

/// syscall
pub fn getegid() -> Result<usize, libc::c_int> {
    eprintln!("SC> getegid() = {}", FAKE_GID);
    Ok(FAKE_GID)
}

/// Convert an unsigned slice to a signed slice
pub trait TrySigned<T>: Sized {
    /// The type returned in the event of a conversion error.
    type Error;

    /// Performs the conversion.
    fn try_signed(value: &[T]) -> Result<Self, Self::Error>;
}

impl TrySigned<u8> for &[i8] {
    type Error = core::num::TryFromIntError;

    fn try_signed(value: &[u8]) -> Result<Self, Self::Error> {
        for c in value {
            i8::try_from(*c)?;
        }

        let len = value.len();
        let ptr = value.as_ptr() as *const i8;

        Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
    }
}
