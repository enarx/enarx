// SPDX-License-Identifier: Apache-2.0

//! process syscalls

use super::BaseSyscallHandler;
use crate::syscall::{KernelSigAction, KernelSigSet, FAKE_GID, FAKE_PID, FAKE_UID};
use crate::untrusted::{AddressValidator, UntrustedRef, UntrustedRefMut, Validate};
use crate::{request, Result};

/// process syscalls
pub trait ProcessSyscallHandler: BaseSyscallHandler + AddressValidator + Sized {
    /// syscall
    fn arch_prctl(&mut self, code: libc::c_int, addr: libc::c_ulong) -> Result;

    /// Proxy an exit() syscall
    fn exit(&mut self, status: libc::c_int) -> ! {
        self.trace("exit", 1);

        #[allow(unused_must_use)]
        loop {
            unsafe { self.proxy(request!(libc::SYS_exit => status)) };
            self.attacked();
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
            self.attacked();
        }
    }

    /// Do a set_tid_address() syscall
    ///
    /// This is currently unimplemented and returns a dummy thread id.
    fn set_tid_address(&mut self, _tidptr: *const libc::c_int) -> Result {
        self.trace("set_tid_address", 1);
        // FIXME
        //eprintln!("SC> set_tid_address(…) = 1");
        Ok([1.into(), 0.into()])
    }

    /// Do a rt_sigaction() system call
    ///
    /// We don't support signals yet. So, fake success.
    fn rt_sigaction(
        &mut self,
        signum: libc::c_int,
        act: UntrustedRef<KernelSigAction>,
        oldact: UntrustedRefMut<KernelSigAction>,
        size: usize,
    ) -> Result {
        self.trace("rt_sigaction", 4);

        const SIGRTMAX: libc::c_int = 64; // TODO: add to libc crate
        static mut ACTIONS: [KernelSigAction; SIGRTMAX as usize] = [[0; 4]; SIGRTMAX as usize];

        if signum >= SIGRTMAX || size != 8 {
            return Err(libc::EINVAL);
        }

        unsafe {
            if !oldact.as_ptr().is_null() {
                let oldact = oldact.validate(self).ok_or(libc::EFAULT)?;
                *(oldact) = ACTIONS[signum as usize];
            }

            if !act.as_ptr().is_null() {
                let act = act.validate(self).ok_or(libc::EFAULT)?;
                ACTIONS[signum as usize] = *act;
            }
        }

        Ok(Default::default())
    }
    /// Do a rt_sigprocmask() syscall
    ///
    /// We don't support signals yet. So, fake success.
    fn rt_sigprocmask(
        &mut self,
        _how: libc::c_int,
        _set: UntrustedRef<KernelSigSet>,
        _oldset: UntrustedRefMut<KernelSigSet>,
        _sigsetsize: libc::size_t,
    ) -> Result {
        // FIXME
        self.trace("rt_sigprocmask", 4);
        Ok(Default::default())
    }

    /// Do a sigaltstack() syscall
    ///
    /// This is currently unimplemented and returns success.
    fn sigaltstack(
        &mut self,
        _ss: UntrustedRef<libc::stack_t>,
        _old_ss: UntrustedRefMut<libc::stack_t>,
    ) -> Result {
        self.trace("sigaltstack", 2);

        Ok(Default::default())
    }
    /// syscall
    fn getpid(&mut self) -> Result {
        self.trace("getpid", 0);
        Ok([FAKE_PID.into(), 0.into()])
    }

    /// Do a getuid() syscall
    fn getuid(&mut self) -> Result {
        self.trace("getuid", 0);
        Ok([FAKE_UID.into(), 0.into()])
    }

    /// Do a getgid() syscall
    fn getgid(&mut self) -> Result {
        self.trace("getgid", 0);
        Ok([FAKE_GID.into(), 0.into()])
    }

    /// Do a geteuid() syscall
    fn geteuid(&mut self) -> Result {
        self.trace("geteuid", 0);
        Ok([FAKE_UID.into(), 0.into()])
    }

    /// Do a getegid() syscall
    fn getegid(&mut self) -> Result {
        self.trace("getegid", 0);
        Ok([FAKE_GID.into(), 0.into()])
    }
}
