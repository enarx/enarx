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
pub(crate) mod usermem;

use core::arch::asm;
use core::arch::x86_64::CpuidResult;
use core::ffi::{c_int, c_size_t, c_ulong, c_void};
use core::fmt::Write;
use core::mem::size_of;
use core::ptr::read_unaligned;
use core::ptr::NonNull;

use sallyport::guest::Handler as _;
use sallyport::guest::{self, Platform, ThreadLocalStorage};
use sallyport::item::enarxcall::sgx::{Report, ReportData, TargetInfo, TECH};
use sallyport::item::enarxcall::SYS_GETATT;
use sallyport::item::syscall::{ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_FS, ARCH_SET_GS};
use sallyport::libc::{off_t, EINVAL, EMSGSIZE, ENOSYS, STDERR_FILENO};

use crate::handler::usermem::UserMemScope;
use crate::{DEBUG, ENARX_EXEC_END, ENARX_EXEC_START, ENCL_SIZE};
use sgx::ssa::StateSaveArea;
use sgx::ssa::Vector;
use x86_64::instructions::segmentation::Segment64;
use x86_64::registers::segmentation::{FS, GS};
use x86_64::VirtAddr;

// Opcode constants, details in Volume 2 of the Intel 64 and IA-32 Architectures Software
// Developer's Manual
const OP_SYSCALL: u16 = 0x050f;
const OP_CPUID: u16 = 0xa20f;

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
        code: c_int,
        addr: c_ulong,
    ) -> sallyport::Result<()> {
        let encl_addr = self.ssa.gpr.fsbase as c_ulong & !(ENCL_SIZE - 1) as c_ulong;
        let encl_end = encl_addr + ENCL_SIZE as c_ulong;

        if addr < encl_addr || addr > encl_end {
            return Err(EINVAL);
        }

        match code {
            // Emulate Seccomp with ENOSYS (instead of EINVAL).
            ARCH_SET_FS => unsafe {
                FS::write_base(VirtAddr::new(addr));
                self.ssa.gpr.fsbase = addr
            },
            ARCH_SET_GS => unsafe {
                GS::write_base(VirtAddr::new(addr));
                self.ssa.gpr.gsbase = addr
            },
            ARCH_GET_FS => return Err(ENOSYS),
            ARCH_GET_GS => return Err(ENOSYS),
            _ => return Err(EINVAL),
        }
        Ok(())
    }

    fn brk(
        &mut self,
        _platform: &impl Platform,
        addr: Option<NonNull<c_void>>,
    ) -> sallyport::Result<NonNull<c_void>> {
        Ok(NonNull::new(
            crate::heap::HEAP
                .write()
                .brk(addr.map(|v| v.as_ptr() as usize).unwrap_or(0)) as _,
        )
        .unwrap())
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

    // Until EDMM, we can't change any page permissions.
    // What you get is what you get. Fake success.
    fn mprotect(
        &mut self,
        _platform: &impl Platform,
        _addr: NonNull<c_void>,
        _len: c_size_t,
        _prot: c_int,
    ) -> sallyport::Result<()> {
        Ok(())
    }

    fn mmap(
        &mut self,
        _platform: &impl Platform,
        addr: Option<NonNull<c_void>>,
        length: c_size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> sallyport::Result<NonNull<c_void>> {
        Ok(NonNull::new(crate::heap::HEAP.write().mmap::<c_void>(
            addr.map(|v| v.as_ptr() as usize).unwrap_or(0),
            length,
            prot,
            flags,
            fd,
            offset,
        )?)
        .unwrap())
    }

    fn munmap(
        &mut self,
        _platform: &impl Platform,
        addr: NonNull<c_void>,
        length: c_size_t,
    ) -> sallyport::Result<()> {
        crate::heap::HEAP
            .write()
            .munmap::<c_void>(addr.as_ptr() as _, length)
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

    fn get_attestation(
        &mut self,
        platform: &impl Platform,
        hash: usize,
        hash_len: usize,
        buf: usize,
        buf_len: usize,
    ) -> Result<[usize; 2], c_int> {
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

        let mut target_info = TargetInfo::default();

        self.get_sgx_target_info(&mut target_info)?;

        // Generate Report
        let report: Report = target_info.enclu_ereport(&ReportData(hash));

        let len = self.get_sgx_quote(&report, buf)?;

        Ok([len, TECH])
    }

    fn handle_syscall(&mut self) {
        debug!(self, "syscall {} ", self.ssa.gpr.rax as usize);

        let orig_rdx = self.ssa.gpr.rdx;
        let nr = self.ssa.gpr.rax as usize;

        let usermemscope = UserMemScope;

        match nr as i64 {
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

        debug!(self, "= {}\n", self.ssa.gpr.rax as isize);
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
        let shim_start = ENCL_SIZE as u64;
        let enarx_exec_start = &ENARX_EXEC_START as *const _ as u64;
        let enarx_exec_end = &ENARX_EXEC_END as *const _ as u64;

        let exec_range = enarx_exec_start..enarx_exec_end;

        if exec_range.contains(&rip) {
            let rip_pie = rip - enarx_exec_start;
            debugln!(self, "E {:>#016x}", rip_pie);
        } else {
            let rip_pie = (shim_start - 1) & rip;
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
