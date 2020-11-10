// SPDX-License-Identifier: Apache-2.0

//! syscall interface layer between assembler and rust

use crate::addr::{HostVirtAddr, ShimPhysUnencryptedAddr};
use crate::asm::_enarx_asm_triple_fault;
use crate::eprintln;
use crate::frame_allocator::FRAME_ALLOCATOR;
use crate::hostcall::{self, HostCall, HOST_CALL};
use crate::paging::SHIM_PAGETABLE;
use crate::payload::{NEXT_BRK_RWLOCK, NEXT_MMAP_RWLOCK};
use core::convert::TryFrom;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use primordial::{Address, Register};
use sallyport::{Cursor, Request};
use spinning::MutexGuard;
use syscall::{SyscallHandler, ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_FS, ARCH_SET_GS, SEV_TECH};
use untrusted::{AddressValidator, UntrustedRef, UntrustedRefMut, Validate};
use x86_64::registers::{rdfsbase, rdgsbase, wrfsbase, wrgsbase};
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::{align_up, VirtAddr};

#[repr(C)]
struct X8664DoubleReturn {
    rax: u64,
    rdx: u64,
}

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

    push   rbx
    mov    rbx, rsp

    # Arguments in registers:
    # SYSV:    rdi, rsi, rdx, rcx, r8, r9
    # SYSCALL: rdi, rsi, rdx, r10, r8, r9 and syscall number in rax
    mov    rcx,                     r10

    # save registers
    push   rdi
    push   rsi
    push   rdx
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
    add    rsp,                     0x8               # skip rdx
    pop    rsi
    pop    rdi

    pop    rbx

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

/// Handle a syscall in rust
#[allow(clippy::many_single_char_names)]
extern "sysv64" fn syscall_rust(
    a: Register<usize>,
    b: Register<usize>,
    c: Register<usize>,
    d: Register<usize>,
    e: Register<usize>,
    f: Register<usize>,
    nr: usize,
) -> X8664DoubleReturn {
    let orig_rdx: usize = c.into();

    let mut h = Handler {
        hostcall: None,
        argv: [a.into(), b.into(), c.into(), d.into(), e.into(), f.into()],
    };

    let ret = h.syscall(a, b, c, d, e, f, nr);

    match ret {
        Err(e) => X8664DoubleReturn {
            rax: e.checked_neg().unwrap() as _,
            // Preserve `rdx` as it is normally not clobbered with a syscall
            rdx: orig_rdx as _,
        },
        Ok([rax, rdx]) => X8664DoubleReturn {
            rax: rax.into(),
            rdx: rdx.into(),
        },
    }
}

/// FIXME
struct Handler {
    hostcall: Option<MutexGuard<'static, HostCall<'static>>>,
    argv: [usize; 6],
}

impl AddressValidator for Handler {
    #[inline(always)]
    fn validate_const_mem_fn(&self, _ptr: *const (), _size: usize) -> bool {
        // FIXME: https://github.com/enarx/enarx/issues/630
        true
    }

    #[inline(always)]
    fn validate_mut_mem_fn(&self, _ptr: *mut (), _size: usize) -> bool {
        // FIXME: https://github.com/enarx/enarx/issues/630
        true
    }
}

impl SyscallHandler for Handler {
    unsafe fn proxy(&mut self, req: Request) -> sallyport::Result {
        let block = self
            .hostcall
            .get_or_insert_with(|| HOST_CALL.try_lock().unwrap())
            .as_mut_block();
        block.msg.req = req;
        self.hostcall
            .get_or_insert_with(|| HOST_CALL.try_lock().unwrap())
            .hostcall()
    }

    fn attacked(&mut self) -> ! {
        // provoke triple fault, causing a VM shutdown
        unsafe { _enarx_asm_triple_fault() };
    }

    fn translate_shim_to_host_addr<T>(&self, buf: *const T) -> *const T {
        let buf_address = Address::from(buf);
        let phys_unencrypted = ShimPhysUnencryptedAddr::try_from(buf_address).unwrap();
        Register::<usize>::from(HostVirtAddr::from(phys_unencrypted)).into()
    }

    fn new_cursor(&mut self) -> Cursor {
        self.hostcall
            .get_or_insert_with(|| HOST_CALL.try_lock().unwrap())
            .as_mut_block()
            .cursor()
    }

    fn trace(&mut self, name: &str, argc: usize) {
        eprint!("{}(", name);
        for (i, arg) in self.argv[..argc].iter().copied().enumerate() {
            let prefix = if i > 0 { ", " } else { "" };
            eprint!("{}{:#x}", prefix, arg);
        }

        eprintln!(")");
    }

    fn get_attestation(&mut self) -> sallyport::Result {
        self.trace("get_att", 0);
        Ok([0.into(), SEV_TECH.into()])
    }

    fn exit(&mut self, status: i32) -> ! {
        self.trace("exit", 1);
        hostcall::shim_exit(status);
    }

    fn exit_group(&mut self, status: i32) -> ! {
        self.trace("exit_group", 1);
        hostcall::shim_exit(status);
    }

    fn arch_prctl(&mut self, code: i32, addr: u64) -> sallyport::Result {
        self.trace("arch_prctl", 2);
        match code {
            ARCH_SET_FS => {
                // FIXME: check `addr` value
                unsafe {
                    wrfsbase(addr);
                }
                eprintln!("SC> arch_prctl(ARCH_SET_FS, {:#x}) = 0", addr);
                Ok(Default::default())
            }
            ARCH_GET_FS => {
                let addr = UntrustedRefMut::from(addr as *mut libc::c_ulong);
                let addr = addr.validate(self).ok_or(libc::EFAULT)?;
                unsafe {
                    *addr = rdfsbase();
                }
                Ok(Default::default())
            }
            ARCH_SET_GS => {
                // FIXME: check `addr` value
                unsafe {
                    wrgsbase(addr);
                }
                eprintln!("SC> arch_prctl(ARCH_SET_GS, {:#x}) = 0", addr);
                Ok(Default::default())
            }
            ARCH_GET_GS => {
                let addr = UntrustedRefMut::from(addr as *mut libc::c_ulong);
                let addr = addr.validate(self).ok_or(libc::EFAULT)?;
                unsafe {
                    *addr = rdgsbase();
                }
                Ok(Default::default())
            }
            x => {
                eprintln!("SC> arch_prctl({:#x}, {:#x}) = -EINVAL", x, addr);
                Err(libc::EINVAL)
            }
        }
    }

    fn mprotect(&mut self, addr: UntrustedRef<u8>, len: usize, prot: i32) -> sallyport::Result {
        self.trace("mprotect", 3);
        let addr = addr.as_ptr();

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

        Ok(Default::default())
    }

    fn mmap(
        &mut self,
        addr: UntrustedRef<u8>,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> sallyport::Result {
        self.trace("mmap", 6);

        const PA: i32 = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

        match (addr.as_ptr(), length, prot, flags, fd, offset) {
            (ptr, _, _, PA, -1, 0) if ptr.is_null() => {
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
                        eprintln!("SC> mmap(0, {}, …) = ENOMEM", length);
                        libc::ENOMEM
                    })?;
                eprintln!("SC> mmap(0, {}, …) = {:#?}", length, mem_slice.as_ptr());
                unsafe {
                    core::ptr::write_bytes(mem_slice.as_mut_ptr(), 0, length);
                }
                *NEXT_MMAP_RWLOCK.write().deref_mut() = virt_addr + (len_aligned as u64);

                //eprintln!("next_mmap = {:#x}", *NEXT_MMAP_RWLOCK::read().deref());

                Ok([mem_slice.as_ptr().into(), Default::default()])
            }
            (addr, ..) => {
                eprintln!("SC> mmap({:#?}, {}, …)", addr, length);
                unimplemented!()
            }
        }
    }

    fn munmap(&mut self, _addr: UntrustedRef<u8>, _lenght: usize) -> sallyport::Result {
        self.trace("munmap", 2);
        Ok(Default::default())
    }

    fn brk(&mut self, addr: *const u8) -> sallyport::Result {
        self.trace("brk", 1);
        let len;

        let next_brk = *NEXT_BRK_RWLOCK.read().deref();
        let virt_addr = next_brk;

        match addr as usize {
            0 => {
                eprintln!("SC> brk({:#?}) = {:#x}", addr, next_brk.as_u64());
                Ok([next_brk.as_u64().into(), Default::default()])
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
                        return Ok([n.into(), Default::default()]);
                    }

                    // n most likely wrong
                    return Err(libc::EINVAL);
                }

                len = n
                    .checked_sub(next_brk.as_u64() as usize)
                    .ok_or(libc::EINVAL)?;
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

                Ok([n.into(), Default::default()])
            }
        }
    }

    fn madvise(
        &mut self,
        _addr: *const libc::c_void,
        _length: usize,
        _advice: i32,
    ) -> sallyport::Result {
        self.trace("madvise", 3);
        Ok(Default::default())
    }
}
