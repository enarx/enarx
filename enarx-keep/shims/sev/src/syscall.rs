// SPDX-License-Identifier: Apache-2.0

//! syscall interface layer between assembler and rust

use crate::addr::{HostVirtAddr, ShimPhysAddr, ShimVirtAddr};
use crate::eprintln;
use crate::frame_allocator::FRAME_ALLOCATOR;
use crate::hostcall::{self, shim_write_all, HostFd, HOST_CALL};
use crate::paging::SHIM_PAGETABLE;
use crate::payload::{NEXT_BRK_RWLOCK, NEXT_MMAP_RWLOCK};
use core::convert::TryFrom;
use core::ops::{Deref, DerefMut};
use memory::Address;
use sallyport::request;
use x86_64::registers::wrfsbase;
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::{align_up, VirtAddr};

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
    const KERNEL_RSP_OFF: usize = memoffset::offset_of!(TaskStateSegment, privilege_stack_table);
    // TaskStateSegment.privilege_stack_table[3]
    const USR_RSP_OFF: usize = memoffset::offset_of!(TaskStateSegment, privilege_stack_table)
        + 3 * core::mem::size_of::<u64>();

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
    swapgs                                            # restore gs

    # Arguments in registers:
    # SYSV:    rdi, rsi, rdx, rcx, r8, r9
    # SYSCALL: rdi, rsi, rdx, r10, r8, r9 and syscall number in rax
    mov    rcx,                     r10

    # save registers
    push   rdi
    push   rsi
    push   rdx
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
    pop    rdx
    pop    rsi
    pop    rdi

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
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    nr: usize,
) -> usize {
    /*
        #[cfg(debug_assertions)]
        eprintln!(
            "SC> raw: syscall({}, {:#X}, {:#X}, {:#X}, {}, {}, {:#X})",
            nr, a, b, c, d, e, f
        );
    */
    let h = Handler::new(a, b, c, d, e, f);

    let res = match nr as i64 {
        libc::SYS_exit => h.exit(),
        libc::SYS_exit_group => h.exit_group(),
        libc::SYS_read => h.read(),
        libc::SYS_write => h.write(),
        libc::SYS_writev => h.writev(),
        libc::SYS_mmap => h.mmap(),
        libc::SYS_munmap => h.munmap(),
        libc::SYS_arch_prctl => h.arch_prctl(),
        libc::SYS_set_tid_address => h.set_tid_address(),
        libc::SYS_rt_sigaction => h.rt_sigaction(),
        libc::SYS_rt_sigprocmask => h.rt_sigprocmask(),
        libc::SYS_sigaltstack => h.sigaltstack(),
        libc::SYS_getrandom => h.getrandom(),
        libc::SYS_brk => h.brk(),
        libc::SYS_ioctl => h.ioctl(),
        libc::SYS_mprotect => h.mprotect(),

        syscall => {
            //panic!("SC> unsupported syscall: {}", syscall);
            eprintln!("SC> unsupported syscall: {}", syscall);
            Err(libc::ENOSYS)
        }
    };
    res.unwrap_or_else(|e| e.checked_neg().unwrap() as usize) as usize
}

struct Handler {
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
}

impl Handler {
    #[allow(clippy::many_single_char_names)]
    pub fn new(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> Self {
        Self { a, b, c, d, e, f }
    }
    pub fn exit(&self) -> ! {
        eprintln!("SC> exit({})", self.a);
        hostcall::shim_exit(self.a as _);
    }

    pub fn exit_group(&self) -> ! {
        eprintln!("SC> exit_group({})", self.a);
        hostcall::shim_exit(self.a as _);
    }

    pub fn read(&self) -> Result<usize, libc::c_int> {
        let fd = self.a;
        let data = self.b as *mut u8;
        let len = self.c;
        let mut host_call = HOST_CALL.try_lock().ok_or(libc::EIO)?;

        let trusted: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(data, len) };

        let block = host_call.as_mut_block();

        let c = block.cursor();
        let (_, buf) = unsafe { c.alloc::<u8>(trusted.len()).or(Err(libc::EMSGSIZE))? };

        let buf_address = Address::from(buf.as_ptr());
        let shim_virt_address = ShimVirtAddr::try_from(buf_address).map_err(|_| libc::EFAULT)?;
        let host_virt: HostVirtAddr<_> = ShimPhysAddr::from(shim_virt_address).into();

        block.msg.req = request!(libc::SYS_read => fd, host_virt, len);
        let result = unsafe { host_call.hostcall() };
        let result_len: usize = result.map(|r| r[0].into())?;

        if trusted.len() < result_len {
            panic!("syscall read buffer overflow");
        }

        let block = host_call.as_mut_block();
        let c = block.cursor();
        let (_, untrusted) = unsafe { c.alloc(result_len).or(Err(libc::EMSGSIZE))? };
        trusted[..result_len].copy_from_slice(untrusted);

        Ok(result_len)
    }

    pub fn write(&self) -> Result<usize, libc::c_int> {
        let fd = self.a;
        let data = self.b as *const u8;
        let len = self.c;
        let mut host_call = HOST_CALL.try_lock().ok_or(libc::EIO)?;
        unsafe {
            let slice = core::slice::from_raw_parts(data, len);
            // FIXME: allocate unencrypted pages
            host_call.write(fd, slice).map(|r| r[0].into())
        }
    }

    pub fn writev(&self) -> Result<usize, libc::c_int> {
        let fd = unsafe { HostFd::from_raw_fd(self.a as _) };
        let iovec =
            unsafe { core::slice::from_raw_parts_mut(self.b as *mut libc::iovec, self.c as usize) };
        let bufsize = iovec
            .iter()
            .fold(0, |a: usize, e| a.checked_add(e.iov_len).unwrap());

        for vec in iovec {
            let data = unsafe {
                core::slice::from_raw_parts(vec.iov_base as *const u8, vec.iov_len as usize)
            };
            // FIXME: allocate unencrypted pages
            shim_write_all(fd, data)?;
        }
        Ok(bufsize)
    }

    pub fn arch_prctl(&self) -> Result<usize, libc::c_int> {
        const ARCH_SET_GS: usize = 0x1001;
        const ARCH_SET_FS: usize = 0x1002;
        const ARCH_GET_FS: usize = 0x1003;
        const ARCH_GET_GS: usize = 0x1004;

        match self.a {
            ARCH_SET_FS => {
                let value: u64 = self.b as _;
                unsafe {
                    wrfsbase(value);
                }
                eprintln!("SC> arch_prctl(ARCH_SET_FS, {:#X}) = 0", value);
                Ok(0)
            }
            ARCH_GET_FS => unimplemented!(),
            ARCH_SET_GS => unimplemented!(),
            ARCH_GET_GS => unimplemented!(),
            x => {
                eprintln!("SC> arch_prctl({:#X}, {:#X}) = -EINVAL", x, self.b);
                Err(libc::EINVAL)
            }
        }
    }

    pub fn mprotect(&self) -> Result<usize, libc::c_int> {
        use x86_64::structures::paging::mapper::Mapper;

        let addr = self.a as u64;
        let len = self.b;
        let prot = self.c as i32;
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

        if prot & libc::PROT_WRITE != 0 {
            flags |= PageTableFlags::WRITABLE;
        }

        if prot & libc::PROT_EXEC == 0 {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        let mut page_table = SHIM_PAGETABLE.write();

        let start_addr = VirtAddr::new(addr);
        let start_page: Page = Page::containing_address(start_addr);
        let end_page: Page = Page::containing_address(start_addr + len - 1u64);
        let page_range = Page::range_inclusive(start_page, end_page);
        for page in page_range {
            unsafe {
                match page_table.update_flags(page, flags) {
                    Ok(flush) => flush.flush(),
                    Err(e) => {
                        dbg!(e);
                        return Err(libc::EINVAL);
                    }
                }
            }
        }
        eprintln!("SC> mprotect({:#X}, {}, {}, …) = 0", self.a, self.b, self.c);

        Ok(0)
    }

    pub fn mmap(&self) -> Result<usize, libc::c_int> {
        const PA: i32 = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

        let addr = self.a;
        let len = self.b;
        let prot = self.c as i32;
        let flags = self.d as i32;
        let fd = self.e as i32;
        let offset = self.f;

        match (addr, len, prot, flags, fd, offset) {
            (0, _, _, PA, -1, 0) => {
                let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

                if prot & libc::PROT_WRITE != 0 {
                    flags |= PageTableFlags::WRITABLE;
                }

                if prot & libc::PROT_EXEC == 0 {
                    flags |= PageTableFlags::NO_EXECUTE;
                }

                let virt_addr = *NEXT_MMAP_RWLOCK.read().deref();
                let len_aligned = align_up(len as _, Page::<Size4KiB>::SIZE) as _;

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
                        eprintln!("SC> mmap({:#X}, {}, …) = ENOMEM", self.a, self.b,);
                        libc::ENOMEM
                    })?;
                eprintln!(
                    "SC> mmap({:#X}, {}, …) = {:#?}",
                    self.a,
                    self.b,
                    mem_slice.as_ptr()
                );
                unsafe {
                    core::ptr::write_bytes(mem_slice.as_mut_ptr(), 0, len);
                }
                *NEXT_MMAP_RWLOCK.write().deref_mut() = virt_addr + (len_aligned as u64);

                //eprintln!("next_mmap = {:#X}", *NEXT_MMAP_RWLOCK::read().deref());

                Ok(mem_slice.as_ptr() as usize)
            }
            _ => {
                eprintln!("SC> mmap({:#X}, {}, …)", self.a, self.b);
                todo!();
            }
        }
    }

    pub fn brk(&self) -> Result<usize, libc::c_int> {
        let len;

        let next_brk = *NEXT_BRK_RWLOCK.read().deref();
        let virt_addr = next_brk;

        match self.a {
            0 => {
                eprintln!("SC> brk({:#X}) = {:#X}", self.a, next_brk.as_u64());
                Ok(next_brk.as_u64() as _)
            }
            n => {
                len = n.checked_sub(next_brk.as_u64() as usize).unwrap();

                // FIXME
                assert_eq!(
                    len.checked_rem(Page::<Size4KiB>::SIZE as usize),
                    Some(0),
                    "brk not page aligned"
                );

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
                        eprintln!("SC> brk({:#X}) = ENOMEM", self.a);
                        libc::ENOMEM
                    })?;

                *NEXT_BRK_RWLOCK.write() = virt_addr + (len_aligned as u64);

                eprintln!("SC> brk({:#X}) = {:#X}", self.a, n);

                Ok(n)
            }
        }
    }

    /// Do a ioctl() syscall
    ///
    pub fn ioctl(&self) -> Result<usize, libc::c_int> {
        match (self.a, self.b as i32) {
            (1, libc::TIOCGWINSZ) | (2, libc::TIOCGWINSZ) => {
                // simulate TIOCGWINSZ
                let p: *mut libc::winsize = self.c as _;
                let winsize = libc::winsize {
                    ws_row: 40,
                    ws_col: 80,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                unsafe {
                    p.write_volatile(winsize);
                }
                eprintln!("SC> ioctl({}, TIOCGWINSZ, {{ws_row=40, ws_col=80, ws_xpixel=0, ws_ypixel=0}}) = 0", self.a);
                Ok(0)
            }
            _ => Err(libc::EINVAL),
        }
    }
    /// Do a set_tid_address() syscall
    ///
    /// This is currently unimplemented and returns a dummy thread id.
    pub fn set_tid_address(&self) -> Result<usize, libc::c_int> {
        // FIXME
        eprintln!("SC> set_tid_address(…) = 1");
        Ok(1)
    }

    /// Do a rt_sigaction() syscall
    ///
    /// This is currently unimplemented and returns success.
    pub fn rt_sigaction(&self) -> Result<usize, libc::c_int> {
        // FIXME
        eprintln!("SC> rt_sigaction(…) = 0");
        Ok(0)
    }

    /// Do a rt_sigaction() syscall
    ///
    /// This is currently unimplemented and returns success.
    pub fn rt_sigprocmask(&self) -> Result<usize, libc::c_int> {
        // FIXME
        eprintln!("SC> rt_sigprocmask(…) = 0");
        Ok(0)
    }

    /// Do a munmap() syscall
    ///
    /// This is currently unimplemented and returns success.
    pub fn munmap(&self) -> Result<usize, libc::c_int> {
        // FIXME
        eprintln!("SC> munmap(…) = 0");
        Ok(0)
    }

    /// Do a sigaltstack() syscall
    ///
    /// This is currently unimplemented and returns success.
    pub fn sigaltstack(&self) -> Result<usize, libc::c_int> {
        // FIXME
        eprintln!("SC> sigaltstack(…) = 0");
        Ok(0)
    }

    /// Do a getrandom() syscall
    pub fn getrandom(&self) -> Result<usize, libc::c_int> {
        let flags = self.c as u64;
        let flags = flags & !((libc::GRND_NONBLOCK | libc::GRND_RANDOM) as u64);

        if flags != 0 {
            return Err(libc::EINVAL);
        }

        let trusted =
            unsafe { core::slice::from_raw_parts_mut(self.a as *mut u8, self.b as usize) };

        for (i, chunk) in trusted.chunks_mut(8).enumerate() {
            let mut el = 0u64;
            loop {
                if unsafe { core::arch::x86_64::_rdrand64_step(&mut el) } == 1 {
                    chunk.copy_from_slice(&el.to_ne_bytes()[..chunk.len()]);
                    break;
                } else {
                    if (flags & libc::GRND_NONBLOCK as u64) != 0 {
                        eprintln!("SC> getrandom(…) = -EAGAIN");
                        return Err(libc::EAGAIN);
                    }
                    if (flags & libc::GRND_RANDOM as u64) != 0 {
                        eprintln!("SC> getrandom(…) = {}", i.checked_mul(8).unwrap());
                        return Ok(i.checked_mul(8).unwrap());
                    }
                }
            }
        }
        eprintln!("SC> getrandom(…) = {}", trusted.len());

        Ok(trusted.len())
    }
}
