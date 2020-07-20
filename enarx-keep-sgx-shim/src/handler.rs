// SPDX-License-Identifier: Apache-2.0

use crate::Layout;

use bounds::{Contains, Line, Span};
use memory::Register;
use sallyport::{request, Block, Request};
use sgx_types::ssa::StateSaveArea;

use core::fmt::Write;
use core::mem::size_of;
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
    block: &'a mut Block,
}

impl<'a> Write for Handler<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if s.as_bytes().len() == 0 {
            return Ok(());
        }

        let mut cursor = self.block.cursor();
        let untrusted = cursor.copy_slice(s.as_bytes()).or(Err(core::fmt::Error))?;

        // Do the syscall; replace encrypted memory with unencrypted memory.
        let req = request!(libc::SYS_write => libc::STDERR_FILENO, untrusted, untrusted.len());
        let res = unsafe { self.proxy(req) };

        match res {
            Ok(res) if usize::from(res[0]) > s.bytes().len() => self.attacked(),
            Ok(res) if usize::from(res[0]) == s.bytes().len() => Ok(()),
            _ => Err(core::fmt::Error),
        }
    }
}

impl<'a> Handler<'a> {
    /// Create a new handler
    pub fn new(
        layout: &'a Layout,
        aex: &'a mut StateSaveArea,
        ctx: &'a Context,
        block: &'a mut Block,
    ) -> Self {
        Self {
            aex,
            ctx,
            layout,
            block,
        }
    }

    #[inline(never)]
    unsafe fn proxy(&mut self, req: Request) -> Result<[Register<usize>; 2], libc::c_int> {
        self.block.msg.req = req;

        let ret = syscall(
            self.block.msg.req.arg[0].raw() as u64, // rdi
            self.block.msg.req.arg[1].raw() as u64, // rsi
            self.block.msg.req.arg[2].raw() as u64, // rdx
            self.aex,
            self.block.msg.req.arg[4].raw() as u64, // r8
            self.block.msg.req.arg[5].raw() as u64, // r9
            self.block.msg.req.arg[3].raw() as u64, // r10
            self.block.msg.req.num.raw() as u64,    // rax
            self.ctx,
        );

        self.block.msg.rep = Ok([ret.into(), 0usize.into()]).into();
        self.block.msg.rep.into()
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

        #[allow(unused_must_use)]
        loop {
            unsafe { self.proxy(request!(libc::SYS_exit => code)) };
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
        #[allow(unused_must_use)]
        loop {
            unsafe { self.proxy(request!(libc::SYS_exit_group => code)) };
        }
    }

    /// Do a getuid() syscall
    pub fn getuid(&mut self) -> u64 {
        self.trace("getuid", 0);

        match unsafe { self.proxy(request!(libc::SYS_getuid)) } {
            Ok(res) => res[0].raw() as u64,
            Err(code) => code as u64,
        }
    }

    /// Do a read() syscall
    pub fn read(&mut self) -> u64 {
        self.trace("read", 3);

        // Allocate some unencrypted memory from the Block.
        let cursor = self.block.cursor();
        let slice: &mut [u8] = match unsafe { cursor.alloc(self.aex.gpr.rdx.into()) } {
            Ok(slice) => slice,
            Err(_) => return -libc::EMSGSIZE as u64,
        };

        // Do the syscall; replace encrypted memory with unencrypted memory.
        let req = request!(libc::SYS_read => self.aex.gpr.rdi, slice, slice.len());
        let res = unsafe { self.proxy(req) };

        match res {
            Ok(res) => {
                if usize::from(res[0]) > self.aex.gpr.rdx.into() {
                    self.attacked();
                }

                let tbuf = unsafe { self.aex.gpr.rsi.as_slice_mut(self.aex.gpr.rdx.into()) };

                // Reallocate some unencrypted memory from the Block.
                let cursor = self.block.cursor();
                let slice: &mut [u8] = match unsafe { cursor.alloc(self.aex.gpr.rdx.into()) } {
                    Ok(slice) => slice,
                    Err(_) => return -libc::EMSGSIZE as u64,
                };

                // Copy the unencrypted memory into encrypted memory.
                tbuf.copy_from_slice(&slice[..tbuf.len()]);

                res[0].into()
            }

            Err(code) => -code as u64,
        }
    }

    /// Do a write() syscall
    pub fn write(&mut self) -> u64 {
        self.trace("write", 3);

        let input: &[u8] = unsafe { self.aex.gpr.rsi.as_slice(self.aex.gpr.rdx.into()) };

        // Copy the encrypted input into unencrypted memory.
        let cursor = self.block.cursor();
        let untrusted = match cursor.copy_slice(input).or(Err(libc::EMSGSIZE)) {
            Ok(slice) => slice,
            Err(e) => return -e as u64,
        };

        let req = request!(libc::SYS_write => self.aex.gpr.rdi, untrusted, input.len());

        // Do the syscall; replace encrypted memory with unencrypted memory.
        let res = unsafe { self.proxy(req) };

        match res {
            Ok(res) => {
                if usize::from(res[0]) > input.len() {
                    self.attacked();
                }
                res[0].into()
            }
            Err(code) => -code as u64,
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
        match heap.mmap::<libc::c_void>(
            self.aex.gpr.rdi.raw() as _,
            self.aex.gpr.rsi.raw() as _,
            self.aex.gpr.rdx.raw() as _,
            self.aex.gpr.r10.raw() as _,
            self.aex.gpr.r8.raw() as _,
            self.aex.gpr.r9.raw() as _,
        ) {
            Ok(addr) => addr as _,
            Err(e) => -e as _,
        }
    }

    /// Do a munmap() system call
    pub fn munmap(&mut self) -> u64 {
        self.trace("munmap", 2);

        let mut heap = unsafe { crate::heap::Heap::new(self.layout.heap.into()) };
        match heap.munmap::<libc::c_void>(self.aex.gpr.rdi.raw() as _, self.aex.gpr.rsi.raw() as _)
        {
            Err(e) => -e as _,
            Ok(()) => 0,
        }
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

    /// Do a getrandom() syscall
    pub fn getrandom(&mut self) -> u64 {
        self.trace("getrandom", 3);

        let flags = self.aex.gpr.rdx.raw();
        let flags = flags & !((libc::GRND_NONBLOCK | libc::GRND_RANDOM) as u64);

        if flags != 0 {
            return -libc::EINVAL as u64;
        }

        let trusted = unsafe {
            from_raw_parts_mut(
                self.aex.gpr.rdi.raw() as *mut u8,
                self.aex.gpr.rsi.raw() as usize,
            )
        };

        for (i, chunk) in trusted.chunks_mut(8).enumerate() {
            let mut el = 0u64;
            loop {
                if unsafe { core::arch::x86_64::_rdrand64_step(&mut el) } == 1 {
                    chunk.copy_from_slice(&el.to_ne_bytes()[..chunk.len()]);
                    break;
                } else {
                    if (flags & libc::GRND_NONBLOCK as u64) != 0 {
                        return -libc::EAGAIN as u64;
                    }
                    if (flags & libc::GRND_RANDOM as u64) != 0 {
                        return (i * 8) as u64;
                    }
                }
            }
        }

        trusted.len() as u64
    }
}
