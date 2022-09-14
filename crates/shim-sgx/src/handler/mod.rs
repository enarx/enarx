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
use crate::heap::Heap;
use crate::thread::THREAD_SSAS;
use crate::{shim_address, DEBUG, ENARX_EXEC_END, ENARX_EXEC_START, ENCL_SIZE};

use core::arch::asm;
use core::arch::x86_64::CpuidResult;
use core::ffi::{c_int, c_size_t, c_ulong, c_void};
use core::fmt::Write;
use core::mem::size_of;
use core::ptr::read_unaligned;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use mmledger::Access;
use primordial::{Address, Offset, Page};
use sallyport::guest::Handler as _;
use sallyport::guest::{self, Platform, ThreadLocalStorage};
use sallyport::item::enarxcall::sgx::{Report, ReportData, TargetInfo, TECH};
use sallyport::item::enarxcall::{SYS_GETATT, SYS_GETKEY};
use sallyport::libc::{
    off_t, pid_t, CloneFlags, EACCES, EINVAL, EIO, EMSGSIZE, ENOMEM, ENOSYS, ENOTSUP,
    MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, STDERR_FILENO,
};
use sgx::page::{Class, Flags};
use sgx::ssa::StateSaveArea;
use sgx::ssa::Vector;
use spinning::{Lazy, RwLock};
use x86_64::addr::VirtAddr;
use x86_64::structures::paging::Page as PageAddr;

// Opcode constants, details in Volume 2 of the Intel 64 and IA-32 Architectures Software
// Developer's Manual
const OP_SYSCALL: u16 = 0x050f;
const OP_CPUID: u16 = 0xa20f;

/// The keep heap
pub static HEAP: Lazy<RwLock<Heap>> = Lazy::new(|| {
    let start = unsafe { &ENARX_EXEC_END as *const _ } as usize;
    let end = shim_address() + ENCL_SIZE;
    RwLock::new(Heap::new(Address::new(start), Address::new(end)))
});

// For `Handler::mmap_guest()`
static ZERO: Page = Page::zeroed();

fn is_prot_allowed(prot: c_int) -> bool {
    prot == PROT_READ || prot == (PROT_READ | PROT_WRITE) || prot == (PROT_READ | PROT_EXEC)
}

/// Thread local storage for the current thread
pub struct Handler<'a> {
    block: &'a mut [usize],
    ssa: &'a mut StateSaveArea,
}

impl<'a> Write for Handler<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let buf = s.as_bytes();
        let len = buf.len();
        let mut written = 0;
        while written < len {
            written += self
                .write(STDERR_FILENO, &buf[written..])
                .map_err(|_| core::fmt::Error)? as usize;
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
        static mut TLS: ThreadLocalStorage = ThreadLocalStorage::new();
        // FIXME: proper TLS implementation https://github.com/enarx/enarx/issues/1476
        unsafe { &mut TLS }
    }

    fn arch_prctl(
        &mut self,
        _platform: &impl Platform,
        _code: c_int,
        _addr: c_ulong,
    ) -> sallyport::Result<()> {
        debugln!(self, "arch_prctl should have never been called");
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
                NonNull::new(max.raw() as *mut _).unwrap(),
                addr.raw() - max.raw(),
                PROT_READ | PROT_WRITE,
            )?;
            self.mmap_guest(max, addr - max, PROT_READ | PROT_WRITE);
        }

        Ok(NonNull::new(addr.raw() as *mut _).unwrap())
    }

    fn clone(
        &mut self,
        _flags: CloneFlags,
        _stack: NonNull<c_void>,
        _ptid: Option<&AtomicU32>,
        _ctid: Option<&AtomicU32>,
        _tls: NonNull<c_void>,
    ) -> sallyport::Result<c_int> {
        Err(ENOSYS)
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

        let length = Offset::from_items((len + Page::SIZE - 1) / Page::SIZE);
        let access = Access::from_bits_truncate(prot as usize);
        let mut heap = HEAP.write();

        if let Some(addr) = heap.mmap(None, length, access) {
            let ret = NonNull::new(addr.raw() as *mut c_void).unwrap();

            self.mmap_host(
                NonNull::new(addr.raw() as *mut _).unwrap(),
                length.bytes(),
                PROT_READ | PROT_WRITE,
            )?;
            self.mmap_guest(addr, length, prot);

            // If the previous operations succeeded, the virtual memory area
            // (VMA) is already RW.
            if prot != PROT_READ | PROT_WRITE {
                self.mprotect_unlocked(&mut heap, ret, length.bytes() as c_size_t, prot)
                    .or_else(|e| {
                        self.munmap_unlocked(&mut heap, ret, length.bytes())
                            .and(Err(e))
                    })?;
            }

            Ok(ret)
        } else {
            Err(ENOMEM)
        }
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
}

impl<'a> Handler<'a> {
    fn new(ssa: &'a mut StateSaveArea, block: &'a mut [usize]) -> Self {
        Self { ssa, block }
    }

    /// Finish handling an exception
    pub fn finish(ssa: &'a mut StateSaveArea) {
        if let Some(Vector::InvalidOpcode) = ssa.vector() {
            if let OP_SYSCALL | OP_CPUID = unsafe { read_unaligned(ssa.gpr.rip as _) } {
                // Skip the instruction.
                ssa.gpr.rip += 2;
                return;
            }
        }

        unsafe { asm!("ud2", options(noreturn)) };
    }

    /// Handle an exception
    pub fn handle(ssa: &'a mut StateSaveArea, block: &'a mut [usize]) {
        let mut h = Self::new(ssa, block);

        match h.ssa.vector() {
            Some(Vector::InvalidOpcode) => match unsafe { read_unaligned(h.ssa.gpr.rip as _) } {
                OP_SYSCALL => h.handle_syscall(),
                OP_CPUID => h.handle_cpuid(),
                r => {
                    debugln!(h, "unsupported opcode: {:#04x}", r);
                    h.print_ssa_stack_trace();

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

            #[cfg(feature = "gdb")]
            Some(Vector::Page) => {
                h.print_ssa_stack_trace();
                h.gdb_session();
                let _ = h.exit_group(1);
                unreachable!()
            }

            _ => h.attacked(),
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

    fn get_tid(&mut self) -> pid_t {
        for (i, val) in THREAD_SSAS.iter().enumerate() {
            if val.load(Ordering::Relaxed) == self.ssa as *const _ as usize {
                return i as pid_t;
            }
        }
        panic!("get_tid: SSA not found");
    }

    fn handle_syscall(&mut self) {
        let orig_rdx = self.ssa.gpr.rdx;
        let nr = self.ssa.gpr.rax as usize;

        let tid = self.get_tid();
        debugln!(self, "[{tid}] syscall {nr} …");

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

        debugln!(self, "[{tid}] syscall {nr} = {}", self.ssa.gpr.rax as isize);
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

    /// Acknowledge pages committed by the host with ENCLS[EAUG].
    fn mmap_guest(&mut self, addr: Address<usize, Page>, length: Offset<usize, Page>, prot: c_int) {
        let flags = Flags::from_bits_truncate(prot as u8);

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

        if heap.contains(addr, length) == None {
            return Err(ENOMEM);
        }

        self.mprotect_host(addr_in, length.bytes(), prot)?;

        for i in 0..pages {
            let virt_addr = VirtAddr::new((addr.raw() + i * Page::SIZE) as u64);
            // Safety: The address is guaranteed to be page aligned, because
            // `addr` was checked to be page aligned and only a multiple of
            // pages was added.
            let page_addr = unsafe { PageAddr::from_start_address_unchecked(virt_addr) };

            // TODO: https://github.com/enarx/enarx/issues/1892
            Class::Regular
                .info(Flags::READ | Flags::RESTRICTED)
                .accept(page_addr)
                .unwrap_or_else(|_| self.attacked());

            Class::Regular
                .info(Flags::from_bits_truncate(prot as u8))
                .extend(page_addr);
        }

        let access = Access::from_bits_truncate(prot as usize);
        heap.mmap(Some(addr), length, access);

        Ok(())
    }

    fn munmap_unlocked(
        &mut self,
        heap: &mut Heap,
        addr_in: NonNull<c_void>,
        length_in: c_size_t,
    ) -> sallyport::Result<()> {
        let addr = addr_in.as_ptr() as usize;
        let pages = ((length_in + Page::SIZE - 1) & !(Page::SIZE - 1)) / Page::SIZE;

        if addr & 0xfff != 0 || pages == 0 {
            return Err(EINVAL);
        }

        let addr = Address::new(addr);
        let length = Offset::from_items(pages);

        if heap.contains(addr, length) == None {
            return Ok(());
        }

        // Process the ledger first, before doing anything else, because it can
        // legitly fail when running out of resources.
        heap.munmap(addr, length).map_err(|_| ENOMEM)?;

        // On the other hand, failing in any of these operations is expected to
        // crash the enclave because it is due either to a software bug, or a
        // malicious host.
        self.trim_sgx_pages(addr_in, length.bytes())
            .unwrap_or_else(|_| self.attacked());

        for i in 0..pages {
            let virt_addr = VirtAddr::new((addr.raw() + i * Page::SIZE) as u64);
            // # Safety
            //
            // The address must be page aligned.
            let page_addr = unsafe { PageAddr::from_start_address_unchecked(virt_addr) };

            Class::Trimmed
                .info(Flags::MODIFIED)
                .accept(page_addr)
                .unwrap_or_else(|_| self.attacked());
        }

        self.munmap_host(addr_in, length.bytes())
            .unwrap_or_else(|_| self.attacked());

        Ok(())
    }

    /// Print a stack trace using the SSA registers.
    fn print_ssa_stack_trace(&mut self) {
        if DEBUG {
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
}
