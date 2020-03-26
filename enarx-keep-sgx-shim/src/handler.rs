// SPDX-License-Identifier: Apache-2.0

use nolibc::x86_64::error::Number as ErrNo;
use nolibc::x86_64::syscall::Number as SysCall;
use nolibc::{ArchPrctlTask, Iovec};
use sgx_types::{ssa::StateSaveArea, tcs::Tcs};

use core::{mem::size_of, ops::Range, slice::from_raw_parts_mut};

extern "C" {
    #[no_mangle]
    fn syscall(
        rdi: u64,
        rsi: u64,
        rdx: u64,
        aex: &mut StateSaveArea,
        r8: u64,
        r9: u64,
        r10: u64,
        rax: SysCall,
        ctx: &Context,
    ) -> u64;
}

pub enum Context {}

pub struct Handler<'a> {
    enclave: Range<u64>,
    aex: &'a mut StateSaveArea,
    ctx: &'a Context,
}

impl<'a> Handler<'a> {
    /// Create a new handler
    pub fn new(tcs: &'a Tcs, aex: &'a mut StateSaveArea, ctx: &'a Context) -> Self {
        // Calculate the boundaries of the enclave.
        //
        // The enclave size is a power of two. The enclave is naturally aligned.
        // The TCS is near the bottom and the shim code is near the top.
        //
        // Therefore, from the absolute address of the TCS and some entity in
        // the shim, we can calculate the boundaries of the enclave memory.
        let tcs_addr = tcs as *const _ as u64;
        let top_addr = syscall as usize as u64;
        let size = (top_addr - tcs_addr).next_power_of_two();
        let start = tcs_addr / size * size;

        Self {
            aex,
            ctx,
            enclave: Range {
                start,
                end: start + size,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    unsafe fn syscall(
        &mut self,
        rax: SysCall,
        rdi: u64,
        rsi: u64,
        rdx: u64,
        r10: u64,
        r8: u64,
        r9: u64,
    ) -> u64 {
        syscall(rdi, rsi, rdx, self.aex, r8, r9, r10, rax, self.ctx)
    }

    /// TODO: https://github.com/enarx/enarx/issues/337
    ///
    /// We probably want a circuit breaker here. When we are under attack,
    /// we trip the circuit breaker and exit the enclave. Any attempt to
    /// re-enter the enclave after tripping the circuit breaker causes the
    /// enclave to immediately EEXIT.
    fn attacked(&mut self) -> ! {
        self.exit(1)
    }

    /// Allocate a chunk of untrusted memory.
    fn ualloc(&mut self, bytes: u64) -> Result<*mut u8, ErrNo> {
        let ret = unsafe {
            self.syscall(
                SysCall::MMAP,
                0,
                bytes,
                nolibc::x86_64::PROT_READ | nolibc::x86_64::PROT_WRITE,
                nolibc::x86_64::MAP_PRIVATE | nolibc::x86_64::MAP_ANONYMOUS,
                !0,
                0,
            )
        };

        // Make sure the allocated memory is page-aligned and outside of the enclave.
        if self.enclave.contains(&ret) || self.enclave.contains(&(ret + bytes)) || ret & 0xfff != 0
        {
            self.attacked();
        }

        if let Some(errno) = ErrNo::from_syscall(ret) {
            return Err(errno);
        }

        Ok(ret as *mut u8)
    }

    /// Free a chunk of untrusted memory.
    unsafe fn ufree(&mut self, map: *mut u8, bytes: u64) -> u64 {
        self.syscall(SysCall::MUNMAP, map as _, bytes, 0, 0, 0, 0)
    }

    /// Proxy an exit() syscall
    ///
    /// The optional `code` parameter overrides the value from `aex`.
    pub fn exit<T: Into<Option<u8>>>(&mut self, code: T) -> ! {
        let code = code.into().map(|x| x.into()).unwrap_or(self.aex.gpr.rdi);
        unsafe { self.syscall(SysCall::EXIT, code, 0, 0, 0, 0, 0) };
        panic!()
    }

    /// Proxy an exitgroup() syscall
    ///
    /// The optional `code` parameter overrides the value from `aex`.
    /// TODO: Currently we are only using one thread, so this will behave the
    /// same way as exit(). In the future, this implementation will change.
    pub fn exit_group<T: Into<Option<u8>>>(&mut self, code: T) -> ! {
        let code = code.into().map(|x| x.into()).unwrap_or(self.aex.gpr.rdi);
        unsafe { self.syscall(SysCall::EXIT_GROUP, code, 0, 0, 0, 0, 0) };
        panic!()
    }

    /// Do a getuid() syscall
    pub fn getuid(&mut self) -> u64 {
        unsafe { self.syscall(SysCall::GETUID, 0, 0, 0, 0, 0, 0) }
    }

    /// Do a read() syscall
    pub fn read(&mut self) -> u64 {
        let fd = self.aex.gpr.rdi;
        let buf = self.aex.gpr.rsi as *mut u8;
        let size = self.aex.gpr.rdx;

        // Allocate some unencrypted memory.
        let map = match self.ualloc(size) {
            Err(errno) => return errno.into_syscall(),
            Ok(map) => map,
        };

        unsafe {
            // Do the syscall; replace encrypted memory with unencrypted memory.
            let ret = self.syscall(SysCall::READ, fd, map as _, size, 0, 0, 0);
            self.ufree(map, size);

            // Copy the unencrypted input into encrypted memory.
            if ErrNo::from_syscall(ret).is_none() {
                if ret > size {
                    self.attacked();
                }

                core::ptr::copy_nonoverlapping(map, buf, ret as _);
            }

            ret
        }
    }

    /// Do a write() syscall
    pub fn write(&mut self) -> u64 {
        let fd = self.aex.gpr.rdi;
        let buf = self.aex.gpr.rsi as *const u8;
        let size = self.aex.gpr.rdx;

        // Allocate some unencrypted memory.
        let map = match self.ualloc(size) {
            Err(errno) => return errno.into_syscall(),
            Ok(map) => map,
        };

        unsafe {
            // Copy the encrypted input into unencrypted memory.
            core::ptr::copy_nonoverlapping(buf, map, size as _);

            // Do the syscall; replace encrypted memory with unencrypted memory.
            let ret = self.syscall(SysCall::WRITE, fd, map as _, size, 0, 0, 0);
            self.ufree(map, size);

            if ErrNo::from_syscall(ret).is_none() && ret > size {
                self.attacked();
            }

            ret
        }
    }

    /// Do a set_tid_address() syscall
    // This is currently unimplemented and returns a dummy thread id.
    pub fn set_tid_address(&mut self) -> u64 {
        1
    }

    /// Do an arch_prctl() syscall
    pub fn arch_prctl(&mut self) -> u64 {
        // TODO: Check that addr in %rdx does not point to an unmapped address
        // and is not outside of the process address space.

        match ArchPrctlTask::from(self.aex.gpr.rsi) {
            ArchPrctlTask::ArchSetFs => {
                self.aex.gpr.fsbase = self.aex.gpr.rdx;
                0
            }

            // TODO: Fix me
            ArchPrctlTask::ArchGetFs => ErrNo::ENOSYS.into_syscall(),

            ArchPrctlTask::ArchSetGs => {
                self.aex.gpr.gsbase = self.aex.gpr.rdx;
                0
            }

            // TODO: Fix me
            ArchPrctlTask::ArchGetGs => ErrNo::ENOSYS.into_syscall(),

            _ => ErrNo::EINVAL.into_syscall(),
        }
    }

    /// Do a readv() syscall
    pub fn readv(&mut self) -> u64 {
        let fd = self.aex.gpr.rdi;
        let trusted = unsafe {
            from_raw_parts_mut(self.aex.gpr.rsi as *mut Iovec, self.aex.gpr.rdx as usize)
        };

        // Add up total size of buffers and size of iovec array.
        let bufsize = trusted.iter().fold(0, |a, e| a + e.size);
        let iovecsize = size_of::<Iovec>() * trusted.len();
        let size = bufsize + iovecsize;

        // Allocate some unencrypted memory.
        let map = match self.ualloc(size as u64) {
            Err(errno) => return errno.into_syscall(),
            Ok(map) => unsafe { from_raw_parts_mut(map, size as usize) },
        };

        // Split allocated memory into that used by the iovec struct array and that used by its buffers.
        let (uiovec, ubuffer) = map.split_at_mut(iovecsize);

        // Convert the prefix from a byte slice into an iovec slice.
        let (_, untrusted, _) = unsafe { uiovec.align_to_mut::<Iovec>() };
        if untrusted.len() != trusted.len() {
            self.attacked();
        }

        // Set pointers in unencrypted iovec slice to use the rest of the allocated memory.
        // The offset is into the buffer area allocated immediately after the iovec struct
        // array, measured in bytes.
        let mut offset = 0;
        for (t, mut u) in trusted.iter_mut().zip(untrusted.iter_mut()) {
            u.base = ubuffer[offset..].as_mut_ptr();
            u.size = t.size;
            offset += t.size;
        }

        // Do the syscall; replace encrypted memory with unencrypted memory.
        let ret = unsafe {
            self.syscall(
                SysCall::READV,
                fd,
                untrusted.as_ptr() as _,
                untrusted.len() as u64,
                0,
                0,
                0,
            )
        };

        // Copy the unencrypted input into encrypted memory.
        if ErrNo::from_syscall(ret).is_none() {
            if ret > size as u64 {
                self.attacked();
            }

            let mut offset = 0;
            for (t, u) in trusted.iter_mut().zip(untrusted.iter_mut()) {
                if u.base != ubuffer[offset..].as_mut_ptr() || u.size != t.size {
                    self.attacked();
                }

                t.as_mut().copy_from_slice(u.as_ref());
                offset += t.size;
            }
        }

        unsafe { self.ufree(map.as_ptr() as *mut u8, size as u64) };
        ret
    }
}
