// SPDX-License-Identifier: Apache-2.0

//! FIXME: add docs

macro_rules! debug {
    ($dst:expr, $($arg:tt)*) => {
        #[allow(unused_must_use)] {
            if $crate::DEBUG {
                use core::fmt::Write;
                write!($dst, $($arg)*);
            }
        }
    };
}

macro_rules! debugln {
    ($dst:expr) => { debugln!($dst,) };
    ($dst:expr, $($arg:tt)*) => {
        if $crate::DEBUG {
            use core::fmt::Write;
            let _ = writeln!($dst, $($arg)*);
        }
    };
}

pub(crate) mod gdb;
pub(crate) mod key;
pub(crate) mod usermem;

use crate::handler::usermem::UserMemScope;
use crate::heap::{Access, Heap};
use crate::thread::{
    NewThread, NewThreadFromRegisters, Tcb, Tcs, ThreadMem, NEW_THREAD_QUEUE, THREADS_FREE,
    THREAD_ID_CNT,
};
use crate::{
    shim_address, CSSA_0_STACK_SIZE, CSSA_1_PLUS_STACK_SIZE, DEBUG, ENARX_EXEC_END,
    ENARX_EXEC_START, ENCL_SIZE, NUM_SSA,
};

use core::arch::asm;
use core::arch::x86_64::CpuidResult;
use core::ffi::{c_int, c_size_t, c_ulong, c_void};
use core::fmt::Write;
use core::mem::size_of;
use core::ops::Deref;
use core::ptr::read_unaligned;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use mmledger::{Record, Region, Span};
use primordial::{Address, Offset, Page};
use sallyport::guest::{self, Handler as _, Platform, ThreadLocalStorage};
use sallyport::item::enarxcall::sgx::{Report, ReportData, TargetInfo, TECH};
use sallyport::item::enarxcall::{SYS_GETATT, SYS_GETKEY};
use sallyport::libc::{
    off_t, pid_t, CloneFlags, SYS_clock_gettime, EACCES, EAGAIN, EINVAL, EIO, EMSGSIZE, ENOMEM,
    ENOSYS, ENOTSUP, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, STDERR_FILENO,
};
use sallyport::Error;
use sgx::page::{Class, Flags};
use sgx::ssa::StateSaveArea;
use sgx::ssa::Vector;
use spin::{Lazy, RwLock};
use x86_64::addr::VirtAddr;
use x86_64::structures::idt::PageFaultErrorCode;
use x86_64::structures::paging::Page as PageAddr;

// Opcode constants, details in Volume 2 of the Intel 64 and IA-32 Architectures Software
// Developer's Manual
const OP_SYSCALL: u16 = 0x050f;
const OP_CPUID: u16 = 0xa20f;

/// The keep heap
pub static HEAP: Lazy<RwLock<Heap>> = Lazy::new(|| {
    let start = unsafe { &ENARX_EXEC_END as *const _ } as usize;
    let end = shim_address() + ENCL_SIZE;
    let span: Span = Region::new(Address::new(start), Address::new(end)).into();
    RwLock::new(Heap::new(span.start, span.count))
});

// For `Handler::mmap_guest()`
static ZERO: Page = Page::zeroed();

fn is_prot_allowed(prot: c_int) -> bool {
    prot == PROT_READ || prot == (PROT_READ | PROT_WRITE) || prot == (PROT_READ | PROT_EXEC)
}

fn flags_from_access(access: Access) -> Flags {
    let mut flags = Flags::empty();

    if access.contains(Access::READ) {
        flags |= Flags::READ;
    }

    if access.contains(Access::WRITE) {
        flags |= Flags::WRITE;
    }

    if access.contains(Access::EXECUTE) {
        flags |= Flags::EXECUTE;
    }

    flags
}

fn libc_from_access(access: Access) -> c_int {
    let mut flags = 0;

    if access.contains(Access::READ) {
        flags |= PROT_READ;
    }

    if access.contains(Access::WRITE) {
        flags |= PROT_WRITE;
    }

    if access.contains(Access::EXECUTE) {
        flags |= PROT_EXEC;
    }

    flags
}

fn flags_from_libc(prot: c_int) -> Flags {
    let mut flags = Flags::empty();

    if prot & PROT_READ != 0 {
        flags |= Flags::READ;
    }

    if prot & PROT_WRITE != 0 {
        flags |= Flags::WRITE;
    }

    if prot & PROT_EXEC != 0 {
        flags |= Flags::EXECUTE;
    }

    flags
}

fn access_from_libc(prot: c_int) -> Access {
    let mut access = Access::empty();

    if prot & PROT_READ != 0 {
        access |= Access::READ;
    }

    if prot & PROT_WRITE != 0 {
        access |= Access::WRITE;
    }

    if prot & PROT_EXEC != 0 {
        access |= Access::EXECUTE;
    }

    access
}

trait IntoNonNull {
    fn into_nonnull<T>(self) -> NonNull<T>;
}

impl<R, S> IntoNonNull for Address<R, S>
where
    Address<R, S>: Into<Address<usize, S>>,
{
    fn into_nonnull<T>(self) -> NonNull<T> {
        NonNull::new(self.as_mut_ptr() as *mut T).unwrap()
    }
}

#[derive(PartialEq)]
enum MMapStrategy {
    /// Memory should be mmap'ed directly
    Direct,
    /// Memory should be mmap'ed, when used
    Lazy,
}

/// Thread local storage for the current thread
pub struct Handler<'a> {
    block: &'a mut [usize],
    ssa: &'a mut StateSaveArea,
    tcb: &'a mut Tcb,
    start: u64,
}

impl<'a> Write for Handler<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let buf = s.as_bytes();
        let len = buf.len();
        let mut written = 0;
        while written < len {
            written += self
                .write(STDERR_FILENO, &buf[written..])
                .map_err(|_| core::fmt::Error)?;
        }
        Ok(())
    }
}

impl guest::Handler for Handler<'_> {
    fn sally(&mut self) -> sallyport::Result<()> {
        // prevent earlier writes from being moved beyond this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

        unsafe {
            // Safety: Enclave exit and re-enter should have left all registers intact.
            asm!("syscall");
        }

        // prevent later reads from being moved before this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

        Ok(())
    }

    fn block(&self) -> &[usize] {
        self.block
    }

    fn block_mut(&mut self) -> &mut [usize] {
        self.block
    }

    fn thread_local_storage(&mut self) -> &mut ThreadLocalStorage {
        &mut self.tcb.tls
    }

    fn arch_prctl(
        &mut self,
        _platform: &impl Platform,
        _code: c_int,
        _addr: c_ulong,
    ) -> sallyport::Result<()> {
        let tid = self.tcb.tid;
        debugln!(self, "[{tid}] arch_prctl should have never been called");
        Err(ENOSYS)
    }

    fn brk(
        &mut self,
        _platform: &impl Platform,
        addr: Option<NonNull<c_void>>,
    ) -> sallyport::Result<NonNull<c_void>> {
        let addr = Address::<usize, Page>::new(
            addr.map(|v| (v.as_ptr() as usize + Page::SIZE - 1) & !(Page::SIZE - 1))
                .unwrap_or(0),
        );

        let mut heap = HEAP.write();
        let max = heap.brk_max();
        let addr = heap.brk(addr);

        if addr > max {
            self.mmap_host(
                max.into_nonnull(),
                addr.raw() - max.raw(),
                PROT_READ | PROT_WRITE,
            )?;
            self.mmap_guest(max, addr - max, Flags::READ | Flags::WRITE);
        }

        Ok(addr.into_nonnull())
    }

    fn clone(
        &mut self,
        flags: CloneFlags,
        stack: NonNull<c_void>,
        ptid: Option<&AtomicU32>,
        clear_on_exit: Option<&AtomicU32>,
        tls: NonNull<c_void>,
    ) -> sallyport::Result<c_int> {
        let tid = self.tcb.tid;

        if flags
            != CloneFlags::VM
                | CloneFlags::FS
                | CloneFlags::FILES
                | CloneFlags::SIGHAND
                | CloneFlags::THREAD
                | CloneFlags::SYSVSEM
                | CloneFlags::SETTLS
                | CloneFlags::PARENT_SETTID
                | CloneFlags::CHILD_CLEARTID
                | CloneFlags::DETACHED
        {
            return Err(ENOTSUP);
        }

        let clear_on_exit = clear_on_exit.ok_or(EINVAL)?;
        let ptid = ptid.ok_or(EINVAL)?;

        debugln!(
            self,
            "[{tid}] clone({flags:?}, stack = {stack:p}, ptid = {ptid:p}, clear_on_exit = {clear_on_exit:p}, tls = {tls:p})",
            ptid = ptid as *const _,
            clear_on_exit = clear_on_exit as *const _,
            stack = stack.as_ptr(),
            tls = tls.as_ptr()
        );

        let new_tid = THREAD_ID_CNT.fetch_add(1, Ordering::SeqCst);

        let mut regs = self.ssa.gpr;
        regs.rsp = stack.as_ptr() as _;
        regs.fsbase = tls.as_ptr() as _;

        let mut threads_free_guard = THREADS_FREE.write();

        let addr = if *threads_free_guard == 0 {
            debugln!(self, "[{tid}] allocating new thread");
            self.thread_mem_alloc().map_err(|_| EAGAIN)? as usize
        } else {
            *threads_free_guard -= 1;
            0
        };

        drop(threads_free_guard);

        NEW_THREAD_QUEUE
            .write()
            .push(NewThread::Thread(NewThreadFromRegisters {
                clear_on_exit: clear_on_exit as *const _ as _,
                regs,
                tid: new_tid,
            }))
            .unwrap();

        ptid.store(new_tid as _, Ordering::Relaxed);

        let ret = self.spawn(addr);
        debugln!(self, "[{tid}] spawn() = {ret:#?}");
        ret?;

        Ok(new_tid)
    }

    fn exit(&mut self, status: c_int) -> sallyport::Result<()> {
        let tid = self.tcb.tid;
        let addr = self.tcb.clear_on_exit;
        if let Some(addr) = addr {
            debugln!(self, "[{tid}] clear TID at {addr:p}");
            unsafe { (*addr.as_ptr()).store(0, Ordering::SeqCst) };
            let _ = self.unpark();
        } else {
            debugln!(self, "[{tid}] no TID to clear");
        }

        if self.tcb.return_to_main.rip != 0 {
            self.ssa.gpr.rsp = self.tcb.return_to_main.rsp;
            // The syscall handler will add 2 to rip to skip the syscall instruction (which we don't have anymore)
            self.ssa.gpr.rip = self.tcb.return_to_main.rip - 2;
            self.ssa.gpr.rbx = self.tcb.return_to_main.rbx;
            self.ssa.gpr.rbp = self.tcb.return_to_main.rbp;
            self.ssa.gpr.gsbase = self.tcb.return_to_main.gsbase;
            self.ssa.gpr.fsbase = self.tcb.return_to_main.fsbase;
            self.ssa.gpr.rcx = status as _;

            debugln!(self, "[{tid}] exiting with status {status}",);
        } else {
            debugln!(self, "return_to_main.rip == 0");
            self.print_ssa_stack_trace();
            self.attacked()
        }
        Ok(())
    }

    fn madvise(
        &mut self,
        _platform: &impl Platform,
        _addr: NonNull<c_void>,
        _length: c_size_t,
        _advice: c_int,
    ) -> sallyport::Result<()> {
        Ok(())
    }

    fn mmap(
        &mut self,
        _platform: &impl Platform,
        addr: Option<NonNull<c_void>>,
        len: c_size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> sallyport::Result<NonNull<c_void>> {
        let addr = addr.map(|v| v.as_ptr() as usize).unwrap_or(0);
        // TODO: https://github.com/enarx/enarx/issues/1892
        let prot = prot | PROT_READ;

        if addr != 0 || len == 0 || fd != -1 || offset != 0 || flags != MAP_PRIVATE | MAP_ANONYMOUS
        {
            return Err(ENOTSUP);
        }

        if prot != 0 && !is_prot_allowed(prot) {
            return Err(EACCES);
        }

        self.do_mmap(prot, len, MMapStrategy::Lazy)
    }

    fn mprotect(
        &mut self,
        _platform: &impl Platform,
        addr: NonNull<c_void>,
        len: c_size_t,
        prot: c_int,
    ) -> sallyport::Result<()> {
        let mut heap = HEAP.write();

        self.mprotect_unlocked(&mut heap, addr, len, prot)
    }

    fn munmap(
        &mut self,
        _platform: &impl Platform,
        addr: NonNull<c_void>,
        length: c_size_t,
    ) -> sallyport::Result<()> {
        let mut heap = HEAP.write();

        self.munmap_unlocked(&mut heap, addr, length)
    }

    fn set_tid_address(&mut self, tidptr: &mut c_int) -> sallyport::Result<pid_t> {
        let tid = self.tcb.tid;
        debugln!(
            self,
            "[{tid}] set_tid_address at {tidptr:p}",
            tidptr = tidptr as *const _
        );

        self.tcb.clear_on_exit = NonNull::new(tidptr as *mut c_int as *mut AtomicU32);
        Ok(tid)
    }
}

impl<'a> Handler<'a> {
    fn new(
        ssa: &'a mut StateSaveArea,
        block: &'a mut [usize],
        tcb: &'a mut Tcb,
        start: u64,
    ) -> Self {
        Self {
            ssa,
            block,
            tcb,
            start,
        }
    }

    /// Finish handling an exception
    pub fn finish(ssa: &'a mut StateSaveArea, block: Option<&'a mut [usize]>, tcb: &'a mut Tcb) {
        match ssa.vector() {
            Some(Vector::InvalidOpcode) => {
                if let OP_SYSCALL | OP_CPUID = unsafe { read_unaligned(ssa.gpr.rip as _) } {
                    // Skip the instruction.
                    ssa.gpr.rip += 2;
                    return;
                }
                // Some other invalid opcode.
                panic!();
            }
            Some(Vector::Page) => {
                if let Some(block) = block {
                    let mut h = Self::new(ssa, block, tcb, 0);
                    let error_code =
                        PageFaultErrorCode::from_bits_truncate(h.ssa.misc.exinfo.errcd as u64);
                    let addr = h.ssa.misc.exinfo.maddr as usize;
                    if h.handle_page_fault(addr, error_code).is_ok() {
                        return;
                    }
                }
                // Page fault cannot be handled by the enclave without a block.
                panic!();
            }
            _ => panic!(),
        }
    }

    /// Handle an exception
    pub fn handle(
        ssa: &'a mut StateSaveArea,
        block: &'a mut [usize],
        tcb: &'a mut Tcb,
        start: u64,
    ) {
        let mut h = Self::new(ssa, block, tcb, start);

        match h.ssa.vector() {
            Some(Vector::InvalidOpcode) => match unsafe { read_unaligned(h.ssa.gpr.rip as _) } {
                OP_SYSCALL => h.handle_syscall(),
                OP_CPUID => h.handle_cpuid(),
                r => {
                    debugln!(h, "unsupported opcode: {:#04x}", r);
                    h.print_ssa_stack_trace();

                    #[cfg(feature = "dbg")]
                    if r as u8 == 0xCC {
                        h.ssa.gpr.rip += 1;
                        return;
                    }

                    #[cfg(feature = "gdb")]
                    if r as u8 == 0xCC {
                        let rip = h.ssa.gpr.rip;
                        if unsafe { crate::handler::gdb::unset_bp(rip) } {
                            debugln!(h, "unset_bp: {:#x}", rip);
                        }
                    }

                    #[cfg(feature = "gdb")]
                    h.gdb_session();

                    if r == unsafe { read_unaligned(h.ssa.gpr.rip as _) } {
                        let _ = h.exit_group(1);
                        unreachable!()
                    }
                }
            },

            Some(Vector::Page) => {
                let error_code =
                    PageFaultErrorCode::from_bits_truncate(h.ssa.misc.exinfo.errcd as u64);
                if h.handle_page_fault(h.ssa.misc.exinfo.maddr as usize, error_code)
                    .is_ok()
                {
                    return;
                }

                if cfg!(feature = "gdb") {
                    h.print_ssa_stack_trace();
                    #[cfg(feature = "gdb")]
                    h.gdb_session();
                    let _ = h.exit_group(1);
                } else {
                    h.attacked()
                }
            }

            _ => {
                debugln!(h, "unhandled exception: {:#?}", h.ssa.vector());
                debugln!(h, "Exinfo: {:#?}", h.ssa.misc.exinfo.clone());

                if cfg!(feature = "dbg") {
                    h.print_ssa_stack_trace();
                }
                h.attacked()
            }
        }
    }

    fn get_key(
        &mut self,
        platform: &impl Platform,
        buf: usize,
        buf_len: usize,
    ) -> Result<usize, c_int> {
        if buf == 0 {
            return Ok(key::SGX_KEY_LEN);
        }

        if buf_len > isize::MAX as usize {
            return Err(EINVAL);
        }

        if buf_len < key::SGX_KEY_LEN {
            return Err(EMSGSIZE);
        }

        let buf = platform.validate_slice_mut::<u8>(buf, buf_len)?;

        let key_request = key::Request {
            name: key::Names::SealKey,
            policy: key::Policy::MRSIGNER,
            isvsvn: 0,
            ..Default::default()
        };

        let key_response = key_request.enclu_egetkey().map_err(|e| {
            debugln!(self, "enclu_egetkey: {}", e);
            EIO
        })?;

        buf[..key::SGX_KEY_LEN].copy_from_slice(&key_response.key);

        Ok(key::SGX_KEY_LEN)
    }

    fn get_attestation(
        &mut self,
        platform: &impl Platform,
        hash: usize,
        hash_len: usize,
        buf: usize,
        buf_len: usize,
    ) -> Result<[usize; 2], c_int> {
        if cfg!(feature = "disable-sgx-attestation") {
            return Ok([0, 0]);
        }

        let mut target_info = TargetInfo::default();

        self.get_sgx_target_info(&mut target_info)?;

        let quote_size = self.get_sgx_quote_size()?;

        if buf == 0 {
            return Ok([quote_size, TECH]);
        }

        if buf_len > isize::MAX as usize {
            return Err(EINVAL);
        }

        if buf_len < quote_size {
            return Err(EMSGSIZE);
        }

        if hash_len != 64 {
            return Err(EINVAL);
        }

        let hash = {
            let h = platform.validate_slice::<u8>(hash, hash_len)?;
            let mut hash = [0u8; 64];
            hash.copy_from_slice(h);
            hash
        };

        let buf = platform.validate_slice_mut::<u8>(buf, buf_len)?;

        // Generate Report
        let report: Report = target_info.enclu_ereport(&ReportData(hash));

        let len = self.get_sgx_quote(&report, buf)?;

        Ok([len, TECH])
    }

    fn handle_syscall(&mut self) {
        let orig_rdx = self.ssa.gpr.rdx;
        let nr = self.ssa.gpr.rax as usize;
        let tid = self.tcb.tid;

        // reduce log spam
        if nr != SYS_clock_gettime as _ {
            debugln!(self, "[{tid}] syscall {nr} ...");
        }

        let usermemscope = UserMemScope;

        match nr as i64 {
            SYS_GETKEY => {
                let ret = self.get_key(&usermemscope, self.ssa.gpr.rdi as _, self.ssa.gpr.rsi as _);
                match ret {
                    Err(e) => self.ssa.gpr.rax = -e as u64,
                    Ok(rax) => {
                        self.ssa.gpr.rax = rax as u64;
                        self.ssa.gpr.rdx = orig_rdx;
                    }
                }
            }
            SYS_GETATT => {
                let ret = self.get_attestation(
                    &usermemscope,
                    self.ssa.gpr.rdi as _,
                    self.ssa.gpr.rsi as _,
                    self.ssa.gpr.rdx as _,
                    self.ssa.gpr.r10 as _,
                );
                match ret {
                    Err(e) => self.ssa.gpr.rax = -e as u64,
                    Ok([rax, rdx]) => {
                        self.ssa.gpr.rax = rax as u64;
                        self.ssa.gpr.rdx = rdx as u64;
                    }
                }
            }
            _ => unsafe {
                // Safety:
                // with `usermemscope` we
                // * limit the lifetime of objects created from the userspace syscall arguments to this function.
                // * make sure only memory of the userspace application is addressed
                let ret = self.syscall(
                    &usermemscope,
                    [
                        nr,
                        self.ssa.gpr.rdi as usize,
                        self.ssa.gpr.rsi as usize,
                        self.ssa.gpr.rdx as usize,
                        self.ssa.gpr.r10 as usize,
                        self.ssa.gpr.r8 as usize,
                        self.ssa.gpr.r9 as usize,
                    ],
                );
                match ret {
                    Err(e) => self.ssa.gpr.rax = -e as u64,
                    Ok([rax, _]) => {
                        self.ssa.gpr.rax = rax as u64;
                        self.ssa.gpr.rdx = orig_rdx;
                    }
                }
            },
        };

        self.ssa.gpr.rip += 2;

        // reduce log spam
        if nr != SYS_clock_gettime as _ {
            debugln!(self, "[{tid}] syscall {nr} = {}", self.ssa.gpr.rax as isize);
        }
    }

    fn handle_cpuid(&mut self) {
        let mut cpuid_result: CpuidResult = CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        };

        debug!(
            self,
            "cpuid({:08x}, {:08x})",
            self.ssa.gpr.rax.clone(),
            self.ssa.gpr.rcx.clone(),
        );

        self.cpuid(
            self.ssa.gpr.rax as _,
            self.ssa.gpr.rcx as _,
            &mut cpuid_result,
        )
        .unwrap();

        self.ssa.gpr.rax = cpuid_result.eax.into();
        self.ssa.gpr.rbx = cpuid_result.ebx.into();
        self.ssa.gpr.rcx = cpuid_result.ecx.into();
        self.ssa.gpr.rdx = cpuid_result.edx.into();

        debugln!(
            self,
            " = ({:08x}, {:08x}, {:08x}, {:08x})",
            self.ssa.gpr.rax.clone(),
            self.ssa.gpr.rbx.clone(),
            self.ssa.gpr.rcx.clone(),
            self.ssa.gpr.rdx.clone()
        );

        self.ssa.gpr.rip += 2;
    }

    fn do_mmap(
        &mut self,
        prot: c_int,
        len: usize,
        lazy: MMapStrategy,
    ) -> Result<NonNull<c_void>, Error> {
        if len == 0 {
            return Err(EINVAL);
        }

        let length = Offset::from_items((len + Page::SIZE - 1) / Page::SIZE);
        let access = access_from_libc(prot);
        let mut heap = HEAP.write();

        let Some(addr) = heap.mmap(None, length, access) else {
            debugln!(self, "ERROR heap.mmap() failed!!!!");
            return Err(ENOMEM)
        };

        let ret = addr.into_nonnull();
        debugln!(
            self,
            "mmap({:#?})",
            Record {
                region: Region::new(addr, addr + length),
                access: access | Access::MMAPPED
            }
        );

        if lazy == MMapStrategy::Lazy {
            // Allocate all paged on-demand.
            return Ok(ret);
        }

        if heap.mmap(Some(addr), length, access | Access::MMAPPED) != Some(addr) {
            debugln!(self, "MMAPPED heap is inconsistent");
            self.attacked()
        }

        if let Err(e) = self.mmap_host(addr.into_nonnull(), length.bytes(), PROT_READ | PROT_WRITE)
        {
            debugln!(self, "ERROR mmap_host() = {e:#?}");
            self.attacked()
        }

        self.mmap_guest(addr, length, flags_from_libc(prot));

        // If the previous operations succeeded, the virtual memory area
        // (VMA) is already RW.
        if prot != PROT_READ | PROT_WRITE {
            if let Err(e) = self.mprotect_unlocked(&mut heap, ret, length.bytes() as c_size_t, prot)
            {
                debugln!(self, "ERROR mprotect_unlocked() = {e:#?}");
                self.attacked()
            }
        }
        Ok(ret)
    }

    /// Acknowledge pages committed by the host with ENCLS[EAUG].
    fn mmap_guest(
        &mut self,
        addr: Address<usize, Page>,
        length: Offset<usize, Page>,
        flags: Flags,
    ) {
        let zero_virt_addr = VirtAddr::new(ZERO.as_ptr() as u64);
        // # Safety
        //
        // The address must be page aligned.
        let zero_page_addr = unsafe { PageAddr::from_start_address_unchecked(zero_virt_addr) };

        for i in 0..length.items() {
            let virt_addr = VirtAddr::new((addr.raw() + i * Page::SIZE) as u64);
            // # Safety
            //
            // The address must be page aligned.
            let page_addr = unsafe { PageAddr::from_start_address_unchecked(virt_addr) };

            Class::Regular
                .info(flags)
                .accept_copy(page_addr, zero_page_addr)
                .unwrap_or_else(|_| self.attacked());
        }
    }

    fn mprotect_unlocked(
        &mut self,
        heap: &mut Heap,
        addr_in: NonNull<c_void>,
        length_in: c_size_t,
        prot: c_int,
    ) -> sallyport::Result<()> {
        let addr = addr_in.as_ptr() as usize;
        // TODO: Simplify:
        let pages = ((length_in + Page::SIZE - 1) & !(Page::SIZE - 1)) / Page::SIZE;

        if addr & 0xfff != 0 || pages == 0 {
            return Err(EINVAL);
        }

        if !is_prot_allowed(prot) {
            return Err(EACCES);
        }

        let addr = Address::new(addr);
        let length = Offset::from_items(pages);
        let access = access_from_libc(prot);

        debugln!(self, "heap = {heap:#?}", heap = heap.deref());
        debugln!(
            self,
            "mprotect({:#?}, {:?})",
            &Region {
                start: addr,
                end: addr + length
            },
            access
        );

        match heap.contains(addr, length) {
            None => return Err(ENOMEM),
            Some(access) => {
                if access == Access::empty() {
                    debugln!(
                        self,
                        "mprotect_unlocked previous access ({:#?}",
                        Record {
                            region: Region::new(addr, addr + length),
                            access
                        }
                    );
                    self.attacked();
                }
            }
        }

        heap.protect_with(addr, length, |record| {
            debugln!(self, "mprotect_unlocked working on ({record:#?})");
            if record.access.contains(Access::MMAPPED) {
                if access != record.access {
                    let region = &record.region;
                    let addr = region.start.into_nonnull();
                    let length = (region.end - region.start).bytes();
                    let pages = (region.end - region.start).items();

                    self.mprotect_host(addr, length, prot)
                        .unwrap_or_else(|err| {
                            debugln!(
                                self,
                                "mprotect_unlocked mprotect_host failed access={access:#?} record.access={raccess:#?} ({record:#?}) = {err:#?}",
                                raccess=record.access,
                            );
                            self.attacked();
                        });

                    for i in 0..pages {
                        let virt_addr =
                            VirtAddr::new((region.start + Offset::from_items(i)).as_ptr() as u64);
                        // Safety: The address is guaranteed to be page aligned, because
                        // `addr` was checked to be page aligned and only a multiple of
                        // pages was added.
                        let page_addr =
                            unsafe { PageAddr::from_start_address_unchecked(virt_addr) };

                        // TODO: https://github.com/enarx/enarx/issues/1892
                        Class::Regular
                            .info(Flags::READ | Flags::RESTRICTED)
                            .accept(page_addr)
                            .unwrap_or_else(|_| self.attacked());

                        Class::Regular.info(flags_from_libc(prot)).extend(page_addr);
                    }
                }
                access | Access::MMAPPED
            } else {
                access
            }
        }).unwrap_or_else(|e| {
            debugln!(self, "mprotect_unlocked heap.protect_with failed: {:?}", e);
            self.attacked();
        });

        Ok(())
    }

    fn munmap_unlocked(
        &mut self,
        heap: &mut Heap,
        addr_in: NonNull<c_void>,
        length_in: c_size_t,
    ) -> sallyport::Result<()> {
        let tid = self.tcb.tid;
        let addr = addr_in.as_ptr() as usize;
        let pages = ((length_in + Page::SIZE - 1) & !(Page::SIZE - 1)) / Page::SIZE;

        if addr & 0xfff != 0 || pages == 0 {
            return Err(EINVAL);
        }

        let addr = Address::new(addr);
        let length = Offset::from_items(pages);

        if heap.contains(addr, length).is_none() {
            return Ok(());
        }

        // Process the ledger first, before doing anything else, because it can
        // legitly fail when running out of resources.
        heap.munmap_with(addr, length, move |record: &Record<Access>| {
            debugln!(self, "[{tid}] sgx_unmap({:#?}", record);

            if !record.access.contains(Access::MMAPPED) {
                // if not MMAPPED, we don't have to do anything
                return;
            }

            let region = &record.region;
            let addr = region.start.into_nonnull();
            let length = (region.end - region.start).bytes();
            let pages = (region.end - region.start).items();

            // On the other hand, failing in any of these operations is expected to
            // crash the enclave because it is due either to a software bug, or a
            // malicious host.
            if let Err(e) = self.modify_sgx_page_type(addr, length, Class::Trimmed as _) {
                debugln!(
                    self,
                    "[{tid}] ERROR munmap: modify_sgx_page_type FAILED !!! {e:?}"
                );
                self.attacked();
            }

            for i in 0..pages {
                let virt_addr =
                    VirtAddr::new((region.start + Offset::from_items(i)).as_ptr() as u64);
                // # Safety
                //
                // The address must be page aligned.
                let page_addr = unsafe { PageAddr::from_start_address_unchecked(virt_addr) };

                Class::Trimmed
                    .info(Flags::MODIFIED)
                    .accept(page_addr)
                    .unwrap_or_else(|_| self.attacked());
            }

            self.munmap_host(addr, length)
                .unwrap_or_else(|_| self.attacked());
        })
        .map_err(|_| ENOMEM)?;

        Ok(())
    }

    /// Print a stack trace using the SSA registers.
    fn print_ssa_stack_trace(&mut self) {
        if DEBUG {
            debugln!(self, "{:#x?}", self.ssa.gpr.clone());
            unsafe { self.print_stack_trace(self.ssa.gpr.rip, self.ssa.gpr.rbp) }
        }
    }

    /// Print out `rip` relative to the shim (S) or the exec (E) base address.
    ///
    /// This can be used with `addr2line` and the executable with debug info
    /// to get the function name and line number.
    unsafe fn print_rip(&mut self, rip: u64) {
        let enarx_exec_start = &ENARX_EXEC_START as *const _ as u64;
        let enarx_exec_end = &ENARX_EXEC_END as *const _ as u64;

        let exec_range = enarx_exec_start..enarx_exec_end;

        if exec_range.contains(&rip) {
            let rip_pie = rip - enarx_exec_start;
            debugln!(self, "E {:>#016x}", rip_pie);
        } else {
            let rip_pie = rip - shim_address() as u64;
            debugln!(self, "S {:>#016x}", rip_pie);
        }
    }

    /// Print a stack trace with the old `rbp` stack frame pointers
    unsafe fn print_stack_trace(&mut self, rip: u64, mut rbp: u64) {
        // TODO: parse the elf and actually find the text sections.
        let encl_start = self as *const _ as u64 / ENCL_SIZE as u64 * ENCL_SIZE as u64;
        let encl_end = encl_start + ENCL_SIZE as u64;
        let encl_range = encl_start..encl_end;

        debugln!(self, "TRACE:");

        self.print_rip(rip);

        // Maximum 64 frames
        for _frame in 0..64 {
            if rbp == 0 || rbp & 7 != 0 {
                break;
            }

            if !encl_range.contains(&rbp) {
                debugln!(self, "invalid rbp: {:>#016x}", rbp);
                break;
            }

            match rbp.checked_add(size_of::<usize>() as _) {
                None => break,
                Some(rip_rbp) => {
                    let rip = *(rip_rbp as *const u64);
                    match rip.checked_sub(1) {
                        None => break,
                        Some(0) => break,
                        Some(rip) => {
                            self.print_rip(rip);
                            rbp = *(rbp as *const u64);
                        }
                    }
                }
            }
        }
    }

    fn thread_mem_alloc(&mut self) -> sallyport::Result<*const Tcs> {
        let usermemscope = UserMemScope;

        // Allocate the whole block of memory used for the thread.
        // It is easier to do this in one go and punch holes in it,
        // than to allocate each part separately.
        let addr = self.do_mmap(
            PROT_READ | PROT_WRITE,
            size_of::<ThreadMem>(),
            MMapStrategy::Direct,
        )?;

        // # Safety
        // ThreadMem is a POD type and the memory is aligned and zeroed.
        let tm = unsafe { &mut *(addr.as_ptr() as *mut ThreadMem) };

        let stack_end_1 = NonNull::new(&mut tm.cssa_stack as *mut _ as *mut c_void).unwrap();
        let stack_end_0 = NonNull::new(&mut tm.stack as *mut _ as *mut c_void).unwrap();
        let tcs = &tm.tcs as *const Tcs;
        let ssa = tm.ssa.as_ptr();

        // address is relative to the enclave base (`shim_address()`)
        tm.tcs.ossa = ssa as u64 - shim_address() as u64;
        // start with level 0
        tm.tcs.cssa = 0;
        // number of SSA frames
        tm.tcs.nssa = NUM_SSA as _;
        // address is relative to the enclave base
        tm.tcs.oentry = self.start - shim_address() as u64;

        // unmap stack guard pages, so a stack overflow will cause a page fault
        self.munmap(&usermemscope, stack_end_1, Page::SIZE)
            .unwrap_or_else(|_| self.attacked());
        self.munmap(&usermemscope, stack_end_0, Page::SIZE)
            .unwrap_or_else(|_| self.attacked());

        self.modify_sgx_page_type(
            NonNull::new(tcs as *mut c_void).unwrap(),
            Page::SIZE,
            Class::Tcs as _,
        )
        .unwrap_or_else(|_| self.attacked());

        let virt_addr = VirtAddr::from_ptr(tcs);
        // # Safety
        //
        // The address must be page aligned.
        let page_addr = unsafe { PageAddr::from_start_address_unchecked(virt_addr) };

        Class::Tcs
            .info(Flags::MODIFIED)
            .accept(page_addr)
            .unwrap_or_else(|_| self.attacked());

        Ok(tcs)
    }

    // FIXME: https://github.com/enarx/enarx/issues/2251
    #[allow(dead_code)]
    fn thread_mem_free(&mut self, tcs: *const Tcs) -> sallyport::Result<()> {
        let usermemscope = UserMemScope;

        let tm_start = tcs as usize - CSSA_1_PLUS_STACK_SIZE - CSSA_0_STACK_SIZE - Page::SIZE;
        let tm_addr = NonNull::new(tm_start as *const ThreadMem as *mut c_void).unwrap();

        debugln!(
            self,
            "drop_thread_mem: {:#?} {}",
            tm_addr,
            size_of::<ThreadMem>()
        );

        self.munmap(&usermemscope, tm_addr, size_of::<ThreadMem>())?;

        Ok(())
    }

    fn handle_page_fault(&mut self, addr: usize, error_code: PageFaultErrorCode) -> Result<(), ()> {
        let tid = self.tcb.tid;
        let addr = addr & !(Page::SIZE - 1);

        debugln!(self, "[{tid}] handle_page_fault: {addr:#x} {error_code:?}");

        // check for non-valid flags
        if !error_code
            .difference(
                PageFaultErrorCode::CAUSED_BY_WRITE
                    | PageFaultErrorCode::INSTRUCTION_FETCH
                    | PageFaultErrorCode::USER_MODE,
            )
            .is_empty()
        {
            debugln!(
                self,
                "[{tid}] handle_page_fault: difference {:#?}",
                error_code.difference(
                    PageFaultErrorCode::CAUSED_BY_WRITE
                        | PageFaultErrorCode::INSTRUCTION_FETCH
                        | PageFaultErrorCode::USER_MODE,
                )
            );

            return Err(());
        }

        // check for must have flags
        if !error_code.contains(PageFaultErrorCode::USER_MODE) {
            return Err(());
        }

        let mut heap = HEAP.write();

        let addr = Address::new(addr);
        let length = Offset::from_items(1);

        let access = match heap.contains(addr, length) {
            None => {
                debugln!(
                    self,
                    "[{tid}] handle_page_fault: access empty {:#?}",
                    Region::new(addr, addr + length),
                );
                panic!();
            }
            Some(access) => {
                // check for real page fault
                if !access.contains(Access::READ)
                    || (error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE)
                        && !access.contains(Access::WRITE))
                    || (error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH)
                        && !access.contains(Access::READ | Access::EXECUTE))
                {
                    debugln!(
                        self,
                        "[{tid}] handle_page_fault: real page fault previous access {:#?}",
                        Record {
                            region: Region::new(addr, addr + length),
                            access
                        }
                    );
                    panic!();
                }
                access
            }
        };

        if heap.mmap(Some(addr), length, access | Access::MMAPPED) != Some(addr) {
            debugln!(
                self,
                "[{tid}] handle_page_fault: MMAPPED heap is inconsistent"
            );
            panic!();
        }

        if let Err(e) = self.mmap_host(addr.into_nonnull(), length.bytes(), PROT_READ | PROT_WRITE)
        {
            debugln!(
                self,
                "[{tid}] handle_page_fault: ERROR mmap_host() = {e:#?}"
            );
            panic!();
        }

        self.mmap_guest(addr, length, flags_from_access(access));

        // If the previous operations succeeded, the virtual memory area
        // (VMA) is already RW.
        if access != (Access::READ | Access::WRITE) {
            let ret = addr.into_nonnull();

            if let Err(e) = self.mprotect_unlocked(
                &mut heap,
                ret,
                length.bytes() as c_size_t,
                libc_from_access(access),
            ) {
                debugln!(
                    self,
                    "[{tid}] handle_page_fault: ERROR mprotect_unlocked() = {e:#?}"
                );
                panic!();
            }
        }

        Ok(())
    }
}
