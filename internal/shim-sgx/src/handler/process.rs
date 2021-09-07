// SPDX-License-Identifier: Apache-2.0

use sallyport::syscall::{BaseSyscallHandler, ProcessSyscallHandler};
use sallyport::syscall::{ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_FS, ARCH_SET_GS};

impl<'a> ProcessSyscallHandler for super::Handler<'a> {
    /// Do an arch_prctl() syscall
    fn arch_prctl(&mut self, code: libc::c_int, addr: libc::c_ulong) -> sallyport::Result {
        self.trace("arch_prctl", 2);

        // TODO: Check that addr in %rdx does not point to an unmapped address
        // and is not outside of the process address space.
        match code {
            ARCH_SET_FS => self.gpr.fsbase = addr.into(),
            ARCH_SET_GS => self.gpr.gsbase = addr.into(),
            ARCH_GET_FS => return Err(libc::ENOSYS),
            ARCH_GET_GS => return Err(libc::ENOSYS),
            _ => return Err(libc::EINVAL),
        }

        Ok(Default::default())
    }
}
