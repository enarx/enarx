// SPDX-License-Identifier: Apache-2.0

use crate::Layout;

use memory::Register;
use sallyport::{request, Block, Request};
use sgx::types::ssa::StateSaveArea;

use core::convert::TryInto;
use core::fmt::Write;
use core::slice::{from_raw_parts, from_raw_parts_mut};

const TRACE: bool = false;

// arch_prctl syscalls not available in the libc crate as of version 0.2.69
enumerate::enumerate! {
    #[derive(Copy, Clone)]
    enum ArchPrctlTask: usize {
        ArchSetGs = 0x1001,
        ArchSetFs = 0x1002,
        ArchGetFs = 0x1003,
        ArchGetGs = 0x1004,
    }
}

extern "C" {
    #[no_mangle]
    fn syscall(aex: &mut StateSaveArea, ctx: &Context) -> u64;
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
        if s.as_bytes().is_empty() {
            return Ok(());
        }

        let c = self.block.cursor();
        let (_, untrusted) = c.copy_slice(s.as_bytes()).or(Err(core::fmt::Error))?;

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
    unsafe fn proxy(&mut self, req: Request) -> sallyport::Result {
        self.block.msg.req = req;

        let _ret = syscall(self.aex, self.ctx);

        self.block.msg.rep.into()
    }

    /// When we are under attack, we trip this circuit breaker and
    /// exit the enclave. Any attempt to re-enter the enclave after
    /// tripping the circuit breaker causes the enclave to immediately
    /// EEXIT.
    pub fn attacked(&mut self) -> ! {
        self.exit(1)
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
            .unwrap_or_else(|| self.aex.gpr.rdi);

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
            .unwrap_or_else(|| self.aex.gpr.rdi);
        #[allow(unused_must_use)]
        loop {
            unsafe { self.proxy(request!(libc::SYS_exit_group => code)) };
        }
    }

    /// Do a getuid() syscall
    pub fn getuid(&mut self) -> sallyport::Result {
        self.trace("getuid", 0);
        unsafe { self.proxy(request!(libc::SYS_getuid)) }
    }

    /// Do a read() syscall
    pub fn read(&mut self) -> sallyport::Result {
        self.trace("read", 3);

        let c = self.block.cursor();
        let trusted: &mut [u8] = unsafe { self.aex.gpr.rsi.into_slice_mut(self.aex.gpr.rdx) };
        let (_, untrusted) = unsafe { c.alloc::<u8>(trusted.len()).or(Err(libc::EMSGSIZE))? };

        let req = request!(libc::SYS_read => self.aex.gpr.rdi, untrusted, untrusted.len());
        let ret = unsafe { self.proxy(req)? };

        if trusted.len() < ret[0].into() {
            self.attacked();
        }

        let c = self.block.cursor();
        let (_, untrusted) = unsafe { c.alloc(trusted.len()).or(Err(libc::EMSGSIZE))? };
        trusted.copy_from_slice(untrusted);
        Ok(ret)
    }

    /// Do a write() syscall
    pub fn write(&mut self) -> sallyport::Result {
        self.trace("write", 3);

        let c = self.block.cursor();
        let trusted: &[u8] = unsafe { self.aex.gpr.rsi.into_slice(self.aex.gpr.rdx) };
        let (_, untrusted) = c.copy_slice(trusted).or(Err(libc::EMSGSIZE))?;

        let req = request!(libc::SYS_write => self.aex.gpr.rdi, untrusted, untrusted.len());
        let res = unsafe { self.proxy(req)? };

        if trusted.len() < res[0].into() {
            self.attacked();
        }

        Ok(res)
    }

    /// Do a set_tid_address() syscall
    // This is currently unimplemented and returns a dummy thread id.
    pub fn set_tid_address(&mut self) -> sallyport::Result {
        self.trace("set_tid_address", 1);

        Ok([1.into(), 0.into()])
    }

    /// Do an arch_prctl() syscall
    pub fn arch_prctl(&mut self) -> sallyport::Result {
        self.trace("arch_prctl", 2);

        // TODO: Check that addr in %rdx does not point to an unmapped address
        // and is not outside of the process address space.
        match ArchPrctlTask::from(usize::from(self.aex.gpr.rdi)) {
            ArchPrctlTask::ArchSetFs => self.aex.gpr.fsbase = self.aex.gpr.rsi,
            ArchPrctlTask::ArchSetGs => self.aex.gpr.gsbase = self.aex.gpr.rsi,
            ArchPrctlTask::ArchGetFs => return Err(libc::ENOSYS),
            ArchPrctlTask::ArchGetGs => return Err(libc::ENOSYS),
            _ => return Err(libc::EINVAL),
        }

        Ok(Default::default())
    }

    /// Do a readv() syscall
    pub fn readv(&mut self) -> sallyport::Result {
        self.trace("readv", 3);

        let mut size = 0usize;
        let c = self.block.cursor();
        let trusted = unsafe { self.aex.gpr.rsi.into_slice_mut(self.aex.gpr.rdx) };
        let (c, untrusted) = c
            .copy_slice::<libc::iovec>(trusted)
            .or(Err(libc::EMSGSIZE))?;

        let mut c = c;
        for (t, u) in trusted.iter_mut().zip(untrusted.iter_mut()) {
            let (nc, us) = unsafe { c.alloc::<u8>(t.iov_len).or(Err(libc::EMSGSIZE))? };
            c = nc;
            u.iov_base = us.as_mut_ptr() as _;
            size += u.iov_len;
        }

        let req = request!(libc::SYS_readv => self.aex.gpr.rdi, untrusted, untrusted.len());
        let ret = unsafe { self.proxy(req)? };

        let mut read = ret[0].into();
        if size < read {
            self.attacked();
        }

        let c = self.block.cursor();
        let (c, _) = unsafe { c.alloc::<libc::iovec>(trusted.len()) }.or(Err(libc::EMSGSIZE))?;

        let mut c = c;
        for t in trusted.iter_mut() {
            let ts: &mut [u8] = unsafe { from_raw_parts_mut(t.iov_base as _, t.iov_len) };
            let (nc, us) = unsafe { c.alloc::<u8>(ts.len()).or(Err(libc::EMSGSIZE))? };
            c = nc;
            let sz = core::cmp::min(ts.len(), read);
            ts[..sz].copy_from_slice(&us[..sz]);
            read -= sz;
        }

        Ok(ret)
    }

    /// Do a writev() syscall
    pub fn writev(&mut self) -> sallyport::Result {
        self.trace("writev", 3);

        let mut size = 0usize;
        let c = self.block.cursor();
        let trusted = unsafe { self.aex.gpr.rsi.into_slice_mut(self.aex.gpr.rdx) };
        let (c, untrusted) = c
            .copy_slice::<libc::iovec>(trusted)
            .or(Err(libc::EMSGSIZE))?;

        let mut c = c;
        for (t, mut u) in trusted.iter_mut().zip(untrusted.iter_mut()) {
            let ts = unsafe { from_raw_parts(t.iov_base as *const u8, t.iov_len) };
            let (nc, us) = c.copy_slice(ts).or(Err(libc::EMSGSIZE))?;
            c = nc;
            u.iov_base = us.as_mut_ptr() as _;
            size += u.iov_len;
        }

        let req = request!(libc::SYS_writev => self.aex.gpr.rdi, untrusted, untrusted.len());
        let ret = unsafe { self.proxy(req)? };

        if size < ret[0].into() {
            self.attacked();
        }

        Ok(ret)
    }

    /// Do a brk() system call
    pub fn brk(&mut self) -> sallyport::Result {
        self.trace("brk", 1);

        let mut heap = unsafe { crate::heap::Heap::new(self.layout.heap.into()) };
        let ret = heap.brk(self.aex.gpr.rdi.into());
        Ok([ret.into(), Default::default()])
    }

    /// Do a uname() system call
    pub fn uname(&mut self) -> sallyport::Result {
        self.trace("uname", 1);

        fn fill(buf: &mut [i8; 65], with: &str) {
            let src = with.as_bytes();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = *src.get(i).unwrap_or(&0) as i8;
            }
        }

        let u: *mut libc::utsname = self.aex.gpr.rdi.into();
        let u = unsafe { &mut *u };
        fill(&mut u.sysname, "Linux");
        fill(&mut u.nodename, "localhost.localdomain");
        fill(&mut u.release, "5.6.0");
        fill(&mut u.version, "#1");
        fill(&mut u.machine, "x86_64");

        Ok(Default::default())
    }

    /// Do a mprotect() system call
    // Until EDMM, we can't change any page permissions.
    // What you get is what you get. Fake success.
    pub fn mprotect(&mut self) -> sallyport::Result {
        self.trace("mprotect", 3);

        Ok(Default::default())
    }

    /// Do a mmap() system call
    pub fn mmap(&mut self) -> sallyport::Result {
        self.trace("mmap", 6);

        let mut heap = unsafe { crate::heap::Heap::new(self.layout.heap.into()) };
        let ret = heap.mmap::<libc::c_void>(
            self.aex.gpr.rdi.into(),
            self.aex.gpr.rsi.into(),
            self.aex.gpr.rdx.try_into().or(Err(libc::EINVAL))?,
            self.aex.gpr.r10.try_into().or(Err(libc::EINVAL))?,
            usize::from(self.aex.gpr.r8) as _, // Allow truncation!
            self.aex.gpr.r9.into(),
        )?;

        Ok([ret.into(), Default::default()])
    }

    /// Do a munmap() system call
    pub fn munmap(&mut self) -> sallyport::Result {
        self.trace("munmap", 2);

        let mut heap = unsafe { crate::heap::Heap::new(self.layout.heap.into()) };
        heap.munmap::<libc::c_void>(self.aex.gpr.rdi.into(), self.aex.gpr.rsi.into())?;
        Ok(Default::default())
    }

    /// Do a rt_sigaction() system call
    // We don't support signals yet. So, fake success.
    pub fn rt_sigaction(&mut self) -> sallyport::Result {
        self.trace("rt_sigaction", 4);

        type SigAction = [u64; 4];
        const SIGRTMAX: usize = 64; // TODO: add to libc crate
        static mut ACTIONS: [SigAction; SIGRTMAX] = [[0; 4]; SIGRTMAX];

        let signal: usize = self.aex.gpr.rdi.into();
        let new: *const SigAction = self.aex.gpr.rsi.into();
        let old: *mut SigAction = self.aex.gpr.rdx.into();
        let size: usize = self.aex.gpr.r10.into();

        if signal >= SIGRTMAX || size != 8 {
            return Err(libc::EINVAL);
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

        Ok(Default::default())
    }

    /// Do a rt_sigprocmask() system call
    // We don't support signals yet. So, fake success.
    pub fn rt_sigprocmask(&mut self) -> sallyport::Result {
        self.trace("rt_sigprocmask", 4);

        Ok(Default::default())
    }

    /// Do a sigaltstack() system call
    // We don't support signals yet. So, fake success.
    pub fn sigaltstack(&mut self) -> sallyport::Result {
        self.trace("sigaltstack", 2);

        Ok(Default::default())
    }

    /// Do a getrandom() syscall
    pub fn getrandom(&mut self) -> sallyport::Result {
        self.trace("getrandom", 3);

        let flags: libc::c_uint = self.aex.gpr.rdx.try_into().or(Err(libc::EINVAL))?;
        let flags = flags & !(libc::GRND_NONBLOCK | libc::GRND_RANDOM);

        if flags != 0 {
            return Err(libc::EINVAL);
        }

        let trusted: &mut [u8] = unsafe { self.aex.gpr.rdi.into_slice_mut(self.aex.gpr.rsi) };

        for (i, chunk) in trusted.chunks_mut(8).enumerate() {
            let mut el = 0u64;
            loop {
                if unsafe { core::arch::x86_64::_rdrand64_step(&mut el) } == 1 {
                    chunk.copy_from_slice(&el.to_ne_bytes()[..chunk.len()]);
                    break;
                } else {
                    if flags & libc::GRND_NONBLOCK != 0 {
                        return Err(libc::EAGAIN);
                    }
                    if flags & libc::GRND_RANDOM != 0 {
                        return Ok([(i * 8).into(), Default::default()]);
                    }
                }
            }
        }

        Ok([trusted.len().into(), Default::default()])
    }

    // Do clock_gettime syscall
    pub fn clock_gettime(&mut self) -> sallyport::Result {
        self.trace("clock_gettime", 2);

        let clk_id = self.aex.gpr.rdi;
        let trusted = unsafe { self.aex.gpr.rsi.into_slice_mut(1usize) };

        let c = self.block.cursor();
        let (_, untrusted) = unsafe { c.alloc::<libc::timespec>(1).or(Err(libc::EMSGSIZE))? };
        let req = request!(libc::SYS_clock_gettime => clk_id, untrusted);
        let res = unsafe { self.proxy(req)? };

        if 0usize != res[0].into() {
            self.attacked();
        }

        let c = self.block.cursor();
        let (_, untrusted) = unsafe { c.alloc::<libc::timespec>(1).or(Err(libc::EMSGSIZE))? };
        trusted.copy_from_slice(untrusted);
        Ok(res)
    }
}
