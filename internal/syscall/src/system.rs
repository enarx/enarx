// SPDX-License-Identifier: Apache-2.0

//! system syscalls

use crate::BaseSyscallHandler;
use sallyport::{request, Result};
use untrusted::{AddressValidator, UntrustedRefMut, Validate, ValidateSlice};

/// system syscalls
pub trait SystemSyscallHandler: BaseSyscallHandler + AddressValidator + Sized {
    /// Do a getrandom() syscall
    fn getrandom(
        &mut self,
        buf: UntrustedRefMut<u8>,
        buflen: libc::size_t,
        flags: libc::c_uint,
    ) -> Result {
        self.trace("getrandom", 3);
        let flags = flags & !(libc::GRND_NONBLOCK | libc::GRND_RANDOM);

        if flags != 0 {
            return Err(libc::EINVAL);
        }

        let trusted = buf.validate_slice(buflen, self).ok_or(libc::EFAULT)?;

        for (i, chunk) in trusted.chunks_mut(8).enumerate() {
            let mut el = 0u64;
            loop {
                if unsafe { core::arch::x86_64::_rdrand64_step(&mut el) } == 1 {
                    chunk.copy_from_slice(&el.to_ne_bytes()[..chunk.len()]);
                    break;
                } else {
                    if (flags & libc::GRND_NONBLOCK) != 0 {
                        //eprintln!("SC> getrandom(…) = -EAGAIN");
                        return Err(libc::EAGAIN);
                    }
                    if (flags & libc::GRND_RANDOM) != 0 {
                        //eprintln!("SC> getrandom(…) = {}", i.checked_mul(8).unwrap());
                        return Ok([i.checked_mul(8).unwrap().into(), 0.into()]);
                    }
                }
            }
        }
        //eprintln!("SC> getrandom(…) = {}", trusted.len());

        Ok([trusted.len().into(), 0.into()])
    }

    /// syscall
    fn clock_gettime(
        &mut self,
        clockid: libc::clockid_t,
        tp: UntrustedRefMut<libc::timespec>,
    ) -> Result {
        self.trace("clock_gettime", 2);
        let c = self.new_cursor();

        let (_, buf) = c.alloc::<libc::timespec>(1).or(Err(libc::EMSGSIZE))?;
        let buf = buf[0].as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(buf);

        let result =
            unsafe { self.proxy(request!(libc::SYS_clock_gettime => clockid, host_virt))? };

        let c = self.new_cursor();
        *(tp.validate(self).ok_or(libc::EFAULT)?) = unsafe { c.read().or(Err(libc::EMSGSIZE))?.1 };

        Ok(result)
    }

    /// Do a uname() system call
    fn uname(&mut self, buf: UntrustedRefMut<libc::utsname>) -> Result {
        self.trace("uname", 1);

        fn fill(buf: &mut [i8; 65], with: &str) {
            let src = with.as_bytes();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = *src.get(i).unwrap_or(&0) as i8;
            }
        }

        let u = buf.validate(self).ok_or(libc::EFAULT)?;
        fill(&mut u.sysname, "Linux");
        fill(&mut u.nodename, "localhost.localdomain");
        fill(&mut u.release, "5.6.0");
        fill(&mut u.version, "#1");
        fill(&mut u.machine, "x86_64");

        Ok(Default::default())
    }
}
