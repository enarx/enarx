// SPDX-License-Identifier: Apache-2.0

use crate::Layout;

use bounds::{Contains, Line, Span};
use sgx_types::ssa::StateSaveArea;

use core::fmt::Write;
use core::mem::size_of;
use core::ptr::copy_nonoverlapping;
use core::slice::{from_raw_parts, from_raw_parts_mut};

const TRACE: bool = false;

// The last 4095 numbers are errnos
const ERRNO_BASE: u64 = !0xfff;

// arch_prctl syscalls not available in the libc crate as of version 0.2.69
enumerate::enumerate! {
    #[derive(Copy, Clone)]
    enum ArchPrctlTask: u64 {
        ArchSetGs = 0x1001,
        ArchSetFs = 0x1002,
        ArchGetFs = 0x1003,
        ArchGetGs = 0x1004,
    }
}

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
        rax: u64,
        ctx: &Context,
    ) -> u64;
}

pub enum Context {}

pub struct Handler<'a> {
    pub aex: &'a mut StateSaveArea,
    layout: &'a Layout,
    ctx: &'a Context,
}

impl<'a> Write for Handler<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let len = bytes.len() as _;
        if len == 0 {
            return Ok(());
        }

        // Allocate some unencrypted memory.
        let map = match self.ualloc(len) {
            Err(_) => return Err(core::fmt::Error),
            Ok(map) => map,
        };

        unsafe {
            // Copy the encrypted input into unencrypted memory.
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), map, bytes.len());

            // Do the syscall; replace encrypted memory with unencrypted memory.
            self.syscall(
                libc::SYS_write as u64,
                libc::STDERR_FILENO as u64,
                map as _,
                len,
                0,
                0,
                0,
            );

            self.ufree(map, len);
        }

        Ok(())
    }
}

impl<'a> Handler<'a> {
    /// Create a new handler
    pub fn new(layout: &'a Layout, aex: &'a mut StateSaveArea, ctx: &'a Context) -> Self {
        Self { aex, ctx, layout }
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    unsafe fn syscall(
        &mut self,
        rax: u64,
        rdi: u64,
        rsi: u64,
        rdx: u64,
        r10: u64,
        r8: u64,
        r9: u64,
    ) -> u64 {
        syscall(rdi, rsi, rdx, self.aex, r8, r9, r10, rax, self.ctx)
    }

    /// When we are under attack, we trip this circuit breaker and
    /// exit the enclave. Any attempt to re-enter the enclave after
    /// tripping the circuit breaker causes the enclave to immediately
    /// EEXIT.
    pub fn attacked(&mut self) -> ! {
        self.exit(1)
    }

    /// Allocate a chunk of untrusted memory.
    fn ualloc(&mut self, bytes: u64) -> Result<*mut u8, i64> {
        let ret = unsafe {
            self.syscall(
                libc::SYS_mmap as u64,
                0,
                bytes,
                libc::PROT_READ as u64 | libc::PROT_WRITE as u64,
                libc::MAP_PRIVATE as u64 | libc::MAP_ANONYMOUS as u64,
                !0,
                0,
            )
        };

        // Make sure the allocated memory is page-aligned and outside of the enclave.
        let line = Line::from(Span {
            start: ret,
            count: bytes,
        });
        if self.layout.enclave.contains(&line) || ret & 0xfff != 0 {
            self.attacked();
        }

        if ret > ERRNO_BASE {
            return Err(-(ret as i64));
        }

        Ok(ret as *mut u8)
    }

    /// Free a chunk of untrusted memory.
    unsafe fn ufree(&mut self, map: *mut u8, bytes: u64) -> u64 {
        self.syscall(libc::SYS_munmap as u64, map as _, bytes, 0, 0, 0, 0)
    }

    fn trace(&mut self, name: &str, argc: usize) {
        if !TRACE {
            return;
        }

        let argv = [
            self.aex.gpr.rdi,
            self.aex.gpr.rsi,
            self.aex.gpr.rdx,
            self.aex.gpr.r10,
            self.aex.gpr.r8,
            self.aex.gpr.r9,
        ];

        debug!(self, "{}(", name);
        for (i, arg) in argv[..argc].iter().copied().enumerate() {
            let prefix = if i > 0 { ", " } else { "" };
            debug!(self, "{}0x{:x}", prefix, u64::from(arg));
        }

        debugln!(self, ")");
    }

    /// Proxy an exit() syscall
    ///
    /// The optional `code` parameter overrides the value from `aex`.
    pub fn exit<T: Into<Option<u8>>>(&mut self, code: T) -> ! {
        self.trace("exit", 1);

        let code = code
            .into()
            .map(|x| x.into())
            .unwrap_or_else(|| self.aex.gpr.rdi.raw());
        loop {
            unsafe { self.syscall(libc::SYS_exit as u64, code, 0, 0, 0, 0, 0) };
        }
    }

    /// Proxy an exitgroup() syscall
    ///
    /// The optional `code` parameter overrides the value from `aex`.
    /// TODO: Currently we are only using one thread, so this will behave the
    /// same way as exit(). In the future, this implementation will change.
    pub fn exit_group<T: Into<Option<u8>>>(&mut self, code: T) -> ! {
        self.trace("exit_group", 1);

        let code = code
            .into()
            .map(|x| x.into())
            .unwrap_or_else(|| self.aex.gpr.rdi.raw());
        loop {
            unsafe { self.syscall(libc::SYS_exit_group as u64, code, 0, 0, 0, 0, 0) };
        }
    }

    /// Do a getuid() syscall
    pub fn getuid(&mut self) -> u64 {
        self.trace("getuid", 0);

        unsafe { self.syscall(libc::SYS_getuid as u64, 0, 0, 0, 0, 0, 0) }
    }

    /// Do a read() syscall
    pub fn read(&mut self) -> u64 {
        self.trace("read", 3);

        let fd = self.aex.gpr.rdi.raw();
        let buf = self.aex.gpr.rsi.raw() as *mut u8;
        let size = self.aex.gpr.rdx.raw();

        // Allocate some unencrypted memory.
        let map = match self.ualloc(size) {
            Err(errno) => return errno as u64,
            Ok(map) => map,
        };

        unsafe {
            // Do the syscall; replace encrypted memory with unencrypted memory.
            let ret = self.syscall(libc::SYS_read as u64, fd, map as _, size, 0, 0, 0);

            // Copy the unencrypted input into encrypted memory.
            if ret <= ERRNO_BASE {
                if ret > size {
                    self.attacked();
                }

                copy_nonoverlapping(map, buf, ret as _);
            }

            self.ufree(map, size);
            ret
        }
    }

    /// Do a write() syscall
    pub fn write(&mut self) -> u64 {
        self.trace("write", 3);

        let fd = self.aex.gpr.rdi.raw();
        let buf = self.aex.gpr.rsi.raw() as *const u8;
        let size = self.aex.gpr.rdx.raw();

        // Allocate some unencrypted memory.
        let map = match self.ualloc(size) {
            Err(errno) => return errno as u64,
            Ok(map) => map,
        };

        unsafe {
            // Copy the encrypted input into unencrypted memory.
            copy_nonoverlapping(buf, map, size as _);

            // Do the syscall; replace encrypted memory with unencrypted memory.
            let ret = self.syscall(libc::SYS_write as u64, fd, map as _, size, 0, 0, 0);
            self.ufree(map, size);

            if ret <= ERRNO_BASE && ret > size {
                self.attacked();
            }

            ret
        }
    }

    /// Do a set_tid_address() syscall
    // This is currently unimplemented and returns a dummy thread id.
    pub fn set_tid_address(&mut self) -> u64 {
        self.trace("set_tid_address", 1);

        1
    }

    /// Do an arch_prctl() syscall
    pub fn arch_prctl(&mut self) -> u64 {
        // TODO: Check that addr in %rdx does not point to an unmapped address
        // and is not outside of the process address space.

        self.trace("arch_prctl", 2);

        match ArchPrctlTask::from(self.aex.gpr.rdi.raw()) {
            ArchPrctlTask::ArchSetFs => {
                self.aex.gpr.fsbase = self.aex.gpr.rsi;
                0
            }

            // TODO: Fix me
            ArchPrctlTask::ArchGetFs => -libc::ENOSYS as u64,

            ArchPrctlTask::ArchSetGs => {
                self.aex.gpr.gsbase = self.aex.gpr.rsi;
                0
            }

            // TODO: Fix me
            ArchPrctlTask::ArchGetGs => -libc::ENOSYS as u64,

            _ => -libc::EINVAL as u64,
        }
    }

    /// Do a readv() syscall
    pub fn readv(&mut self) -> u64 {
        self.trace("readv", 3);

        let fd = self.aex.gpr.rdi.raw();
        let trusted = unsafe {
            from_raw_parts_mut(
                self.aex.gpr.rsi.raw() as *mut libc::iovec,
                self.aex.gpr.rdx.raw() as usize,
            )
        };

        // Add up total size of buffers and size of iovec array.
        let bufsize = trusted.iter().fold(0, |a, e| a + e.iov_len);
        let iovecsize = size_of::<libc::iovec>() * trusted.len();
        let size = bufsize + iovecsize;

        // Allocate some unencrypted memory.
        let map = match self.ualloc(size as u64) {
            Err(errno) => return errno as u64,
            Ok(map) => unsafe { from_raw_parts_mut(map, size as usize) },
        };

        // Split allocated memory into that used by the iovec struct array and that used by its buffers.
        let (uiovec, ubuffer) = map.split_at_mut(iovecsize);

        // Convert the prefix from a byte slice into an iovec slice.
        let (_, untrusted, _) = unsafe { uiovec.align_to_mut::<libc::iovec>() };
        if untrusted.len() != trusted.len() {
            self.attacked();
        }

        // Set pointers in unencrypted iovec slice to use the rest of the allocated memory.
        // The offset is into the buffer area allocated immediately after the iovec struct
        // array, measured in bytes.
        let mut offset = 0;
        for (t, mut u) in trusted.iter_mut().zip(untrusted.iter_mut()) {
            u.iov_base = ubuffer[offset..].as_mut_ptr() as *mut _;
            u.iov_len = t.iov_len;
            offset += t.iov_len;
        }

        // Do the syscall; replace encrypted memory with unencrypted memory.
        let ret = unsafe {
            self.syscall(
                libc::SYS_readv as u64,
                fd,
                untrusted.as_ptr() as _,
                untrusted.len() as u64,
                0,
                0,
                0,
            )
        };

        // Copy the unencrypted input into encrypted memory.
        if ret <= ERRNO_BASE {
            if ret > size as u64 {
                self.attacked();
            }

            let mut offset = 0;
            for (t, u) in trusted.iter_mut().zip(untrusted.iter_mut()) {
                let us = &mut ubuffer[offset..][..t.iov_len];
                offset += t.iov_len;

                if u.iov_base != us.as_mut_ptr() as *mut _ || u.iov_len != t.iov_len {
                    self.attacked();
                }

                let ts = unsafe { from_raw_parts_mut(t.iov_base as *mut u8, t.iov_len) };
                ts.copy_from_slice(us);
            }
        }

        unsafe { self.ufree(map.as_ptr() as *mut u8, size as u64) };
        ret
    }

    /// Do a writev() syscall
    pub fn writev(&mut self) -> u64 {
        self.trace("writev", 3);

        let fd = self.aex.gpr.rdi.raw();
        let trusted = unsafe {
            from_raw_parts_mut(
                self.aex.gpr.rsi.raw() as *mut libc::iovec,
                self.aex.gpr.rdx.raw() as usize,
            )
        };

        // Add up total size of buffers and size of iovec array.
        let bufsize = trusted.iter().fold(0, |a, e| a + e.iov_len);
        let iovecsize = size_of::<libc::iovec>() * trusted.len();
        let size = bufsize + iovecsize;

        // Allocate some unencrypted memory.
        let map = match self.ualloc(size as u64) {
            Err(errno) => return errno as u64,
            Ok(map) => unsafe { from_raw_parts_mut(map, size as usize) },
        };

        // Split allocated memory into that used by the iovec struct array
        // and that used by its buffers.
        let (uiovec, ubuffer) = map.split_at_mut(iovecsize);

        // Convert the prefix from a byte slice into an iovec slice.
        let (_, untrusted, _) = unsafe { uiovec.align_to_mut::<libc::iovec>() };
        if untrusted.len() != trusted.len() {
            self.attacked();
        }

        // Set pointers in unencrypted iovec slice to use the rest
        // of the allocated memory, then copy the encrypted input
        // into unencrypted memory. The offset is into the buffer
        // area allocated immediately after the iovec struct array,
        // measured in bytes.
        let mut offset = 0;
        for (t, mut u) in trusted.iter_mut().zip(untrusted.iter_mut()) {
            let ts = unsafe { from_raw_parts(t.iov_base as *const u8, t.iov_len) };
            let us = &mut ubuffer[offset..][..t.iov_len];
            offset += t.iov_len;

            us.copy_from_slice(ts);

            u.iov_base = us.as_mut_ptr() as *mut _;
            u.iov_len = us.len();
        }

        // Do the syscall; replace encrypted memory with unencrypted memory.
        let ret = unsafe {
            self.syscall(
                libc::SYS_writev as u64,
                fd,
                untrusted.as_ptr() as _,
                untrusted.len() as u64,
                0,
                0,
                0,
            )
        };

        unsafe { self.ufree(map.as_ptr() as *mut u8, size as u64) };

        if ret <= ERRNO_BASE && ret > size as u64 {
            self.attacked()
        }

        ret
    }

    /// Do a brk() system call
    pub fn brk(&mut self) -> u64 {
        self.trace("brk", 1);

        let mut heap = unsafe { crate::heap::Heap::new(self.layout.heap.into()) };
        heap.brk(self.aex.gpr.rdi.raw() as _) as _
    }

    /// Do a uname() system call
    pub fn uname(&mut self) -> u64 {
        self.trace("uname", 1);

        fn fill(buf: &mut [i8; 65], with: &str) {
            let src = with.as_bytes();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = *src.get(i).unwrap_or(&0) as i8;
            }
        }

        let utsname = unsafe { &mut *(self.aex.gpr.rdi.raw() as *mut libc::utsname) };
        fill(&mut utsname.sysname, "Linux");
        fill(&mut utsname.nodename, "localhost.localdomain");
        fill(&mut utsname.release, "5.6.0");
        fill(&mut utsname.version, "#1");
        fill(&mut utsname.machine, "x86_64");

        0
    }

    /// Do a mprotect() system call
    // Until EDMM, we can't change any page permissions.
    // What you get is what you get. Fake success.
    pub fn mprotect(&mut self) -> u64 {
        self.trace("mprotect", 3);

        0
    }

    /// Do a mmap() system call
    pub fn mmap(&mut self) -> u64 {
        self.trace("mmap", 6);

        let mut heap = unsafe { crate::heap::Heap::new(self.layout.heap.into()) };
        heap.mmap(
            self.aex.gpr.rdi.raw() as _,
            self.aex.gpr.rsi.raw() as _,
            self.aex.gpr.rdx.raw() as _,
            self.aex.gpr.r10.raw() as _,
            self.aex.gpr.r8.raw() as _,
            self.aex.gpr.r9.raw() as _,
        ) as _
    }

    /// Do a munmap() system call
    pub fn munmap(&mut self) -> u64 {
        self.trace("munmap", 2);

        let mut heap = unsafe { crate::heap::Heap::new(self.layout.heap.into()) };
        heap.munmap(self.aex.gpr.rdi.raw() as _, self.aex.gpr.rsi.raw() as _) as _
    }

    /// Do a rt_sigaction() system call
    // We don't support signals yet. So, fake success.
    pub fn rt_sigaction(&mut self) -> u64 {
        type SigAction = [u64; 4];

        static mut ACTIONS: [SigAction; 64] = [[0; 4]; 64];

        self.trace("rt_sigaction", 4);

        let signal = self.aex.gpr.rdi.raw() as usize;
        let new = self.aex.gpr.rsi.raw() as *const SigAction;
        let old = self.aex.gpr.rdx.raw() as *mut SigAction;
        let size = self.aex.gpr.r10.raw();

        if signal >= unsafe { ACTIONS.len() } || size != 8 {
            return -libc::EINVAL as u64;
        }

        unsafe {
            let tmp = ACTIONS[signal];

            if !new.is_null() {
                ACTIONS[signal] = *new;
            }

            if !old.is_null() {
                *old = tmp;
            }
        }

        0
    }

    /// Do a rt_sigprocmask() system call
    // We don't support signals yet. So, fake success.
    pub fn rt_sigprocmask(&mut self) -> u64 {
        self.trace("rt_sigprocmask", 4);

        0
    }

    /// Do a sigaltstack() system call
    // We don't support signals yet. So, fake success.
    pub fn sigaltstack(&mut self) -> u64 {
        self.trace("sigaltstack", 2);

        0
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn errno_values() {
        assert_eq!(-22i64 as u64, -libc::EINVAL as u64);
        // ERRNO return values are the last 4096 numbers in a u64
        let ret = -libc::EINVAL as u64;
        assert_eq!(Some(libc::EINVAL as i64), Some(-(ret as i64)));
    }
    #[test]
    fn syscall_values() {
        assert_eq!(0u64, libc::SYS_read as u64);
        assert_eq!(libc::SYS_read, 0i64 as i64);
    }
}
