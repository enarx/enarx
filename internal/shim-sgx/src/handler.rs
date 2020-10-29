// SPDX-License-Identifier: Apache-2.0

use crate::hostlib::SYS_CPUID;
use crate::Layout;

use core::fmt::Write;
use sallyport::{request, Block, Cursor, Request};
use sgx::types::ssa::StateSaveArea;
use sgx_heap::Heap;
use syscall::{SyscallHandler, ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_FS, ARCH_SET_GS, SGX_TECH};
use untrusted::{AddressValidator, UntrustedRef, ValidateSlice};

pub const TRACE: bool = false;

extern "C" {
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

        let c = self.new_cursor();
        let (_, untrusted) = c.copy_from_slice(s.as_bytes()).or(Err(core::fmt::Error))?;

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
    pub fn cpuid(&mut self) {
        if TRACE {
            debug!(
                self,
                "cpuid({:08x}, {:08x})",
                usize::from(self.aex.gpr.rax),
                usize::from(self.aex.gpr.rcx)
            );
        }

        self.block.msg.req = request!(SYS_CPUID => self.aex.gpr.rax, self.aex.gpr.rcx);

        unsafe {
            // prevent earlier writes from being moved beyond this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

            syscall(self.aex, self.ctx);

            // prevent later reads from being moved before this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

            self.aex.gpr.rax = self.block.msg.req.arg[0].into();
            self.aex.gpr.rbx = self.block.msg.req.arg[1].into();
            self.aex.gpr.rcx = self.block.msg.req.arg[2].into();
            self.aex.gpr.rdx = self.block.msg.req.arg[3].into();
        }

        if TRACE {
            debugln!(
                self,
                " = ({:08x}, {:08x}, {:08x}, {:08x})",
                usize::from(self.aex.gpr.rax),
                usize::from(self.aex.gpr.rbx),
                usize::from(self.aex.gpr.rcx),
                usize::from(self.aex.gpr.rdx)
            );
        }
    }
}

impl<'a> AddressValidator for Handler<'a> {
    fn validate_const_mem_fn(&self, _ptr: *const (), _size: usize) -> bool {
        // FIXME: https://github.com/enarx/enarx/issues/630
        true
    }

    fn validate_mut_mem_fn(&self, _ptr: *mut (), _size: usize) -> bool {
        // FIXME: https://github.com/enarx/enarx/issues/630
        true
    }
}

impl<'a> SyscallHandler for Handler<'a> {
    fn translate_shim_to_host_addr<T>(&self, buf: *const T) -> *const T {
        buf
    }

    fn new_cursor(&mut self) -> Cursor {
        self.block.cursor()
    }

    unsafe fn proxy(&mut self, req: Request) -> sallyport::Result {
        self.block.msg.req = req;

        // prevent earlier writes from being moved beyond this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

        let _ret = syscall(self.aex, self.ctx);

        // prevent later reads from being moved before this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

        self.block.msg.rep.into()
    }

    /// When we are under attack, we trip this circuit breaker and
    /// exit the enclave. Any attempt to re-enter the enclave after
    /// tripping the circuit breaker causes the enclave to immediately
    /// EEXIT.
    fn attacked(&mut self) -> ! {
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
    fn exit(&mut self, status: libc::c_int) -> ! {
        self.trace("exit", 1);

        #[allow(unused_must_use)]
        loop {
            unsafe { self.proxy(request!(libc::SYS_exit => status)) };
        }
    }

    /// Proxy an exitgroup() syscall
    ///
    /// TODO: Currently we are only using one thread, so this will behave the
    /// same way as exit(). In the future, this implementation will change.
    fn exit_group(&mut self, status: libc::c_int) -> ! {
        self.trace("exit_group", 1);

        #[allow(unused_must_use)]
        loop {
            unsafe { self.proxy(request!(libc::SYS_exit_group => status)) };
        }
    }

    /// Do an arch_prctl() syscall
    fn arch_prctl(&mut self, code: libc::c_int, addr: libc::c_ulong) -> sallyport::Result {
        self.trace("arch_prctl", 2);

        // TODO: Check that addr in %rdx does not point to an unmapped address
        // and is not outside of the process address space.
        match code {
            ARCH_SET_FS => self.aex.gpr.fsbase = addr.into(),
            ARCH_SET_GS => self.aex.gpr.gsbase = addr.into(),
            ARCH_GET_FS => return Err(libc::ENOSYS),
            ARCH_GET_GS => return Err(libc::ENOSYS),
            _ => return Err(libc::EINVAL),
        }

        Ok(Default::default())
    }

    /// Do a readv() syscall
    fn readv(
        &mut self,
        fd: libc::c_int,
        iovec: UntrustedRef<libc::iovec>,
        iovcnt: libc::c_int,
    ) -> sallyport::Result {
        self.trace("readv", 3);

        let mut size = 0usize;
        let trusted = iovec.validate_slice(iovcnt, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        let (c, untrusted) = c
            .copy_from_slice::<libc::iovec>(trusted)
            .or(Err(libc::EMSGSIZE))?;

        let mut c = c;
        for (t, u) in trusted.iter().zip(untrusted.iter_mut()) {
            let (nc, us) = c.alloc::<u8>(t.iov_len).or(Err(libc::EMSGSIZE))?;
            c = nc;
            u.iov_base = us.as_mut_ptr() as _;
            size += u.iov_len;
        }

        let req = request!(libc::SYS_readv => fd, untrusted, untrusted.len());
        let ret = unsafe { self.proxy(req)? };

        let mut read = ret[0].into();
        if size < read {
            self.attacked();
        }

        let c = self.new_cursor();
        let (c, _) = c
            .alloc::<libc::iovec>(trusted.len())
            .or(Err(libc::EMSGSIZE))?;

        let mut c = c;
        for t in trusted.iter() {
            let ts = t.iov_base as *mut u8;
            let ts_len: usize = t.iov_len;

            let sz = core::cmp::min(ts_len, read);

            let nc = unsafe { c.copy_into_raw_parts(ts_len, ts, sz) }.or(Err(libc::EMSGSIZE))?;
            c = nc;

            read -= sz;
        }

        Ok(ret)
    }

    /// Do a writev() syscall
    fn writev(
        &mut self,
        fd: libc::c_int,
        iovec: UntrustedRef<libc::iovec>,
        iovcnt: libc::c_int,
    ) -> sallyport::Result {
        self.trace("writev", 3);

        let mut size = 0usize;
        let trusted = iovec.validate_slice(iovcnt, self).ok_or(libc::EFAULT)?;
        let c = self.new_cursor();
        let (c, untrusted) = c
            .copy_from_slice::<libc::iovec>(trusted)
            .or(Err(libc::EMSGSIZE))?;

        let mut c = c;
        for (t, mut u) in trusted.iter().zip(untrusted.iter_mut()) {
            let (nc, us) = unsafe { c.copy_from_raw_parts(t.iov_base as *const u8, t.iov_len) }
                .or(Err(libc::EMSGSIZE))?;
            c = nc;
            u.iov_base = us as _;
            size += u.iov_len;
        }

        let req = request!(libc::SYS_writev => fd, untrusted, untrusted.len());
        let ret = unsafe { self.proxy(req)? };

        if size < ret[0].into() {
            self.attacked();
        }

        Ok(ret)
    }

    /// Do a brk() system call
    fn brk(&mut self, addr: *const u8) -> sallyport::Result {
        self.trace("brk", 1);

        let mut heap = unsafe { Heap::new(self.layout.heap.into()) };
        let ret = heap.brk(addr as _);
        Ok([ret.into(), Default::default()])
    }

    /// Do a mprotect() system call
    // Until EDMM, we can't change any page permissions.
    // What you get is what you get. Fake success.
    fn mprotect(
        &mut self,
        _addr: UntrustedRef<u8>,
        _len: libc::size_t,
        _prot: libc::c_int,
    ) -> sallyport::Result {
        self.trace("mprotect", 3);

        Ok(Default::default())
    }

    /// Do a mmap() system call
    fn mmap(
        &mut self,
        addr: UntrustedRef<u8>,
        length: libc::size_t,
        prot: libc::c_int,
        flags: libc::c_int,
        fd: libc::c_int,
        offset: libc::off_t,
    ) -> sallyport::Result {
        self.trace("mmap", 6);

        let mut heap = unsafe { Heap::new(self.layout.heap.into()) };
        let ret = heap.mmap::<libc::c_void>(
            addr.as_ptr() as _,
            length,
            prot,
            flags,
            fd, // Allow truncation!
            offset,
        )?;

        Ok([ret.into(), Default::default()])
    }

    /// Do a munmap() system call
    fn munmap(&mut self, addr: UntrustedRef<u8>, lenght: libc::size_t) -> sallyport::Result {
        self.trace("munmap", 2);

        let mut heap = unsafe { Heap::new(self.layout.heap.into()) };
        heap.munmap::<libc::c_void>(addr.as_ptr() as _, lenght)?;
        Ok(Default::default())
    }

    // Do madvise syscall
    // We don't actually support this. So, fake success.
    fn madvise(
        &mut self,
        _addr: *const libc::c_void,
        _length: libc::size_t,
        _advice: libc::c_int,
    ) -> sallyport::Result {
        self.trace("madvise", 3);
        Ok(Default::default())
    }

    // Stub for get_attestation() pseudo syscall
    // See: https://github.com/enarx/enarx-keepldr/issues/31
    fn get_attestation(&mut self) -> sallyport::Result {
        self.trace("get_att", 0);
        Ok([0.into(), SGX_TECH.into()])
    }
}
