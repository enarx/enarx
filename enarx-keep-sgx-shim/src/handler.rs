// SPDX-License-Identifier: Apache-2.0

use crate::Layout;

use nolibc::x86_64::error::Number as ErrNo;
use nolibc::x86_64::syscall::Number as SysCall;
use nolibc::{ArchPrctlTask, Iovec};
use sgx_types::ssa::StateSaveArea;
use span::{Contains, Line, Span};

use core::{mem::size_of, slice::from_raw_parts_mut};

const TRACE: bool = false;

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

pub trait Print<T: ?Sized> {
    fn print(&mut self, data: &T);
}

pub enum Context {}

pub struct Handler<'a> {
    pub aex: &'a mut StateSaveArea,
    layout: &'a Layout,
    ctx: &'a Context,
}

impl<'a> Print<str> for Handler<'a> {
    fn print(&mut self, data: &str) {
        let bytes = data.as_bytes();
        let len = bytes.len() as _;

        // Allocate some unencrypted memory.
        let map = match self.ualloc(len) {
            Err(_) => return,
            Ok(map) => map,
        };

        unsafe {
            // Copy the encrypted input into unencrypted memory.
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), map, bytes.len());

            // Do the syscall; replace encrypted memory with unencrypted memory.
            self.syscall(SysCall::WRITE, nolibc::STDERR, map as _, len, 0, 0, 0);

            self.ufree(map, len);
        }
    }
}

fn hex(byte: u8) -> u8 {
    match byte & 0xf {
        0x0 => b'0',
        0x1 => b'1',
        0x2 => b'2',
        0x3 => b'3',
        0x4 => b'4',
        0x5 => b'5',
        0x6 => b'6',
        0x7 => b'7',
        0x8 => b'8',
        0x9 => b'9',
        0xa => b'a',
        0xb => b'b',
        0xc => b'c',
        0xd => b'd',
        0xe => b'e',
        0xf => b'f',
        _ => panic!(),
    }
}

// Print a reverse hex dump for types that implement Copy
//
// The most common use for this is printing numbers, which are little endian.
// Reversing the bytes makes the output big-endian hex.
impl<'a, T: Copy> Print<T> for Handler<'a> {
    fn print(&mut self, data: &T) {
        let mut output = [*data, *data];
        let output = unsafe { output.align_to_mut::<u8>().1 };

        let input = [*data];
        let input = unsafe { input.align_to::<u8>().1 };

        for (i, byte) in input.iter().rev().cloned().enumerate() {
            output[i * 2] = hex(byte >> 4);
            output[i * 2 + 1] = hex(byte);
        }

        self.print(unsafe { core::str::from_utf8_unchecked(&output) })
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
        let line = Line::from(Span {
            start: ret,
            count: bytes,
        });
        if self.layout.enclave.contains(&line) || ret & 0xfff != 0 {
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

        self.print(name);
        self.print("(");
        for (i, arg) in argv[..argc].iter().enumerate() {
            if i > 0 {
                self.print(", ");
            }

            self.print(arg);
        }

        self.print(")\n");
    }

    /// Proxy an exit() syscall
    ///
    /// The optional `code` parameter overrides the value from `aex`.
    pub fn exit<T: Into<Option<u8>>>(&mut self, code: T) -> ! {
        self.trace("exit", 1);

        let code = code.into().map(|x| x.into()).unwrap_or(self.aex.gpr.rdi);
        loop {
            unsafe { self.syscall(SysCall::EXIT, code, 0, 0, 0, 0, 0) };
        }
    }

    /// Proxy an exitgroup() syscall
    ///
    /// The optional `code` parameter overrides the value from `aex`.
    /// TODO: Currently we are only using one thread, so this will behave the
    /// same way as exit(). In the future, this implementation will change.
    pub fn exit_group<T: Into<Option<u8>>>(&mut self, code: T) -> ! {
        self.trace("exit_group", 1);

        let code = code.into().map(|x| x.into()).unwrap_or(self.aex.gpr.rdi);
        loop {
            unsafe { self.syscall(SysCall::EXIT_GROUP, code, 0, 0, 0, 0, 0) };
        }
    }

    /// Do a getuid() syscall
    pub fn getuid(&mut self) -> u64 {
        self.trace("getuid", 0);

        unsafe { self.syscall(SysCall::GETUID, 0, 0, 0, 0, 0, 0) }
    }

    /// Do a read() syscall
    pub fn read(&mut self) -> u64 {
        self.trace("read", 3);

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

            // Copy the unencrypted input into encrypted memory.
            if ErrNo::from_syscall(ret).is_none() {
                if ret > size {
                    self.attacked();
                }

                core::ptr::copy_nonoverlapping(map, buf, ret as _);
            }

            self.ufree(map, size);
            ret
        }
    }

    /// Do a write() syscall
    pub fn write(&mut self) -> u64 {
        self.trace("write", 3);

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
        self.trace("set_tid_address", 1);

        1
    }

    /// Do an arch_prctl() syscall
    pub fn arch_prctl(&mut self) -> u64 {
        // TODO: Check that addr in %rdx does not point to an unmapped address
        // and is not outside of the process address space.

        self.trace("arch_prctl", 2);

        match ArchPrctlTask::from(self.aex.gpr.rdi) {
            ArchPrctlTask::ArchSetFs => {
                self.aex.gpr.fsbase = self.aex.gpr.rsi;
                0
            }

            // TODO: Fix me
            ArchPrctlTask::ArchGetFs => ErrNo::ENOSYS.into_syscall(),

            ArchPrctlTask::ArchSetGs => {
                self.aex.gpr.gsbase = self.aex.gpr.rsi;
                0
            }

            // TODO: Fix me
            ArchPrctlTask::ArchGetGs => ErrNo::ENOSYS.into_syscall(),

            _ => ErrNo::EINVAL.into_syscall(),
        }
    }

    /// Do a readv() syscall
    pub fn readv(&mut self) -> u64 {
        self.trace("readv", 3);

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

    /// Do a writev() syscall
    pub fn writev(&mut self) -> u64 {
        self.trace("writev", 3);

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

        // Split allocated memory into that used by the iovec struct array
        // and that used by its buffers.
        let (uiovec, ubuffer) = map.split_at_mut(iovecsize);

        // Convert the prefix from a byte slice into an iovec slice.
        let (_, untrusted, _) = unsafe { uiovec.align_to_mut::<Iovec>() };
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
            u.base = ubuffer[offset..].as_mut_ptr();
            u.size = t.size;
            u.as_mut().copy_from_slice(t.as_ref());
            offset += t.size;
        }

        // Do the syscall; replace encrypted memory with unencrypted memory.
        let ret = unsafe {
            self.syscall(
                SysCall::WRITEV,
                fd,
                untrusted.as_ptr() as _,
                untrusted.len() as u64,
                0,
                0,
                0,
            )
        };

        unsafe { self.ufree(map.as_ptr() as *mut u8, size as u64) };

        if ErrNo::from_syscall(ret).is_none() && ret > size as u64 {
            self.attacked()
        }

        ret
    }

    /// Do a brk() system call
    pub fn brk(&mut self) -> u64 {
        self.trace("brk", 1);

        let mut heap = unsafe { crate::heap::Heap::new(self.layout.heap.into()) };
        heap.brk(self.aex.gpr.rdi as _) as _
    }

    /// Do a uname() system call
    pub fn uname(&mut self) -> u64 {
        self.trace("uname", 1);

        fn fill(buf: &mut [u8], with: &str) {
            let src = with.as_bytes();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = *src.get(i).unwrap_or(&0);
            }
        }

        let utsname = unsafe { &mut *(self.aex.gpr.rdi as *mut nolibc::UtsName) };
        fill(&mut utsname.sysname, "Linux");
        fill(&mut utsname.nodename, "localhost.localdomain");
        fill(&mut utsname.release, "5.6.0");
        fill(&mut utsname.version, "#1");
        fill(&mut utsname.machine, "x86_64");

        0
    }
}
