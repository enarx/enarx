// SPDX-License-Identifier: Apache-2.0

//! network syscalls

use super::BaseSyscallHandler;
use crate::untrusted::{AddressValidator, UntrustedRef, UntrustedRefMut, Validate, ValidateSlice};
use crate::{request, Block, Result};

/// network syscalls
pub trait NetworkSyscallHandler: BaseSyscallHandler + AddressValidator + Sized {
    /// syscall
    fn socket(&mut self, domain: libc::c_int, type_: libc::c_int, protocol: libc::c_int) -> Result {
        self.trace("socket", 3);
        unsafe { self.proxy(request!(libc::SYS_socket => domain, type_, protocol)) }
    }

    /// syscall
    fn bind(&mut self, fd: libc::c_int, addr: UntrustedRef<u8>, addrlen: libc::size_t) -> Result {
        self.trace("bind", 3);
        if addrlen > Block::buf_capacity() {
            return Err(libc::EINVAL);
        }

        let addr = addr.validate_slice(addrlen, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();
        let (_, addr) = c.copy_from_slice(addr.as_ref()).or(Err(libc::EMSGSIZE))?;
        let addr = addr.as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(addr);

        unsafe { self.proxy(request!(libc::SYS_bind => fd, host_virt, addrlen)) }
    }

    /// syscall
    fn listen(&mut self, sockfd: libc::c_int, backlog: libc::c_int) -> Result {
        self.trace("listen", 2);
        unsafe { self.proxy(request!(libc::SYS_listen => sockfd, backlog)) }
    }

    /// syscall
    fn getsockname(
        &mut self,
        fd: libc::c_int,
        addr: UntrustedRefMut<u8>,
        addrlen: UntrustedRefMut<libc::socklen_t>,
    ) -> Result {
        self.trace("getsockname", 3);

        let addrlen = addrlen.validate(self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        let (c, block_addr) = c.alloc::<u8>(*addrlen as _).or(Err(libc::EMSGSIZE))?;
        let (_, block_addrlen) = c.write(addrlen).or(Err(libc::EINVAL))?;

        let block_addr_ptr = block_addr[0].as_ptr();
        let block_addr = Self::translate_shim_to_host_addr(block_addr_ptr);
        let block_addrlen = Self::translate_shim_to_host_addr(block_addrlen as _);

        let ret = unsafe {
            self.proxy(request!(libc::SYS_getsockname => fd, block_addr, block_addrlen))
        }?;

        unsafe {
            let c = self.new_cursor();
            let (c, _) = c.alloc::<u8>(*addrlen as _).or(Err(libc::EMSGSIZE))?;
            let (_, block_addrlen) = c.read::<libc::socklen_t>().or(Err(libc::EMSGSIZE))?;

            let addr = addr.validate_slice(*addrlen, self).ok_or(libc::EFAULT)?;

            let len = (*addrlen).min(block_addrlen) as usize;

            let c = self.new_cursor();
            c.copy_into_slice(*addrlen as _, &mut addr[..len])
                .or(Err(libc::EMSGSIZE))?;

            *addrlen = block_addrlen;
        }

        Ok(ret)
    }

    /// syscall
    fn accept(
        &mut self,
        fd: libc::c_int,
        addr: UntrustedRefMut<u8>,
        addrlen: UntrustedRefMut<libc::socklen_t>,
    ) -> Result {
        self.accept4(fd, addr, addrlen, 0)
    }

    /// syscall
    fn accept4(
        &mut self,
        fd: libc::c_int,
        addr: UntrustedRefMut<u8>,
        addrlen: UntrustedRefMut<libc::socklen_t>,
        flags: libc::c_int,
    ) -> Result {
        self.trace("accept4", 4);

        if addr.as_ptr().is_null() {
            return unsafe {
                self.proxy(
                    request!(libc::SYS_accept4 => fd, addr.as_ptr(), addrlen.as_ptr(), flags),
                )
            };
        }

        let addrlen = addrlen.validate(self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        let (c, block_addr) = c.alloc::<u8>(*addrlen as _).or(Err(libc::EMSGSIZE))?;
        let (_, block_addrlen) = c.write(addrlen).or(Err(libc::EINVAL))?;

        let block_addr_ptr = block_addr[0].as_ptr();
        let block_addr = Self::translate_shim_to_host_addr(block_addr_ptr);
        let block_addrlen = Self::translate_shim_to_host_addr(block_addrlen as _);

        let ret = unsafe {
            self.proxy(request!(libc::SYS_accept4 => fd, block_addr, block_addrlen, flags))
        }?;

        unsafe {
            let c = self.new_cursor();
            let (c, _) = c.alloc::<u8>(*addrlen as _).or(Err(libc::EMSGSIZE))?;
            let (_, block_addrlen) = c.read::<libc::socklen_t>().or(Err(libc::EMSGSIZE))?;

            let addr = addr.validate_slice(*addrlen, self).ok_or(libc::EFAULT)?;

            let len = (*addrlen).min(block_addrlen) as usize;

            let c = self.new_cursor();
            c.copy_into_slice(*addrlen as _, &mut addr[..len])
                .or(Err(libc::EMSGSIZE))?;

            *addrlen = block_addrlen;
        }

        Ok(ret)
    }

    /// syscall
    fn connect(
        &mut self,
        fd: libc::c_int,
        addr: UntrustedRef<u8>,
        addrlen: libc::size_t,
    ) -> Result {
        self.trace("connect", 3);
        if addrlen > Block::buf_capacity() {
            return Err(libc::EINVAL);
        }

        let addr = addr.validate_slice(addrlen, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();
        let (_, addr) = c.copy_from_slice(addr.as_ref()).or(Err(libc::EMSGSIZE))?;
        let addr = addr.as_ptr();
        let host_virt = Self::translate_shim_to_host_addr(addr);

        unsafe { self.proxy(request!(libc::SYS_connect => fd, host_virt, addrlen)) }
    }

    /// syscall
    fn recvfrom(
        &mut self,
        fd: libc::c_int,
        buf: UntrustedRefMut<u8>,
        count: libc::size_t,
        flags: libc::c_int,
        src_addr: UntrustedRefMut<u8>,
        addrlen: UntrustedRefMut<libc::socklen_t>,
    ) -> Result {
        self.trace("recvfrom", 6);

        // Limit the read to `Block::buf_capacity()`
        let count = usize::min(count, Block::buf_capacity());

        let addrlen = addrlen.validate(self);

        let len = match addrlen {
            None => 0,
            Some(ref e) => **e,
        };

        if (count + (len as usize)) > Block::buf_capacity() {
            return Err(libc::EINVAL);
        }

        let buf = buf.validate_slice(count, self).ok_or(libc::EFAULT)?;

        let c = self.new_cursor();

        let (c, hostbuf) = c.alloc::<u8>(count).or(Err(libc::EMSGSIZE))?;
        let hostbuf = hostbuf.as_ptr();
        let host_buf_virt = Self::translate_shim_to_host_addr(hostbuf);

        let (host_addr, block_addrlen) = if src_addr.as_ptr().is_null() {
            (src_addr.as_ptr() as usize, 0)
        } else {
            let (c, block_addr) = c.alloc::<u8>(len as _).or(Err(libc::EMSGSIZE))?;
            let block_addr_ptr = block_addr[0].as_ptr();
            let block_addr = Self::translate_shim_to_host_addr(block_addr_ptr);
            let (_c, block_addrlen) = c.write(addrlen.as_deref().unwrap()).or(Err(libc::EINVAL))?;
            let block_addrlen = Self::translate_shim_to_host_addr(block_addrlen as _);
            (block_addr, block_addrlen)
        };

        let ret = unsafe {
            self.proxy(
                request!(libc::SYS_recvfrom => fd, host_buf_virt, count, flags, host_addr, block_addrlen),
            )?
        };

        let result_len: usize = ret[0].into();

        if count < result_len {
            self.attacked();
        }

        if src_addr.as_ptr().is_null() {
            let c = self.new_cursor();
            unsafe {
                c.copy_into_slice(count, &mut buf[..result_len].as_mut())
                    .or(Err(libc::EFAULT))?
            };
        } else {
            let addrlen = addrlen.unwrap();
            let addr = src_addr
                .validate_slice(*addrlen as usize, self)
                .ok_or(libc::EFAULT)?;

            let c = self.new_cursor();
            let c = unsafe {
                c.copy_into_slice(count, &mut buf[..result_len].as_mut())
                    .or(Err(libc::EFAULT))?
            };

            unsafe {
                let (c, addr_buf) = c.alloc::<u8>(*addrlen as _).or(Err(libc::EMSGSIZE))?;
                let (_, block_addrlen) = c.read::<libc::socklen_t>().or(Err(libc::EMSGSIZE))?;

                let len = (*addrlen).min(block_addrlen) as usize;

                addr_buf.as_ptr().copy_to(addr.as_mut_ptr() as _, len);

                *addrlen = block_addrlen;
            }
        }

        Ok(ret)
    }

    /// syscall
    fn sendto(
        &mut self,
        sockfd: libc::c_int,
        buf: UntrustedRef<u8>,
        count: libc::size_t,
        flags: libc::c_int,
        dest_addr: UntrustedRef<u8>,
        addrlen: libc::size_t,
    ) -> Result {
        self.trace("sendto", 6);

        // Limit the write to `Block::buf_capacity()`
        let count = usize::min(count, Block::buf_capacity());

        let buf = buf.validate_slice(count, self).ok_or(libc::EFAULT)?;

        let dest_addr = if dest_addr.as_ptr().is_null() {
            None
        } else {
            Some(
                dest_addr
                    .validate_slice(addrlen, self)
                    .ok_or(libc::EFAULT)?,
            )
        };

        let c = self.new_cursor();
        let (c, buf) = c.copy_from_slice(buf.as_ref()).or(Err(libc::EMSGSIZE))?;
        let buf = buf.as_ptr();
        let buf_host_virt = Self::translate_shim_to_host_addr(buf);

        let addr_host_virt = if let Some(dest_addr) = dest_addr {
            let (_, dest_addr) = c
                .copy_from_slice(dest_addr.as_ref())
                .or(Err(libc::EMSGSIZE))?;
            let dest_addr = dest_addr.as_ptr();
            Self::translate_shim_to_host_addr(dest_addr)
        } else {
            0
        };

        let ret = unsafe {
            self.proxy(request!(libc::SYS_sendto => sockfd, buf_host_virt, count, flags, addr_host_virt, addrlen))?
        };

        let result_len: usize = ret[0].into();

        if result_len > count {
            self.attacked()
        }

        Ok(ret)
    }

    /// syscall
    fn setsockopt(
        &mut self,
        sockfd: libc::c_int,
        level: libc::c_int,
        optname: libc::c_int,
        optval: UntrustedRef<u8>,
        optlen: libc::socklen_t,
    ) -> Result {
        self.trace("setsockopt", 5);

        let optval = optval.validate_slice(optlen, self).ok_or(libc::EFAULT)?;
        let c = self.new_cursor();
        let (_, buf) = c.copy_from_slice(optval).or(Err(libc::EMSGSIZE))?;
        let host_virt = Self::translate_shim_to_host_addr(buf.as_ptr());

        unsafe {
            self.proxy(request!(libc::SYS_setsockopt => sockfd, level,optname, host_virt, optlen))
        }
    }
}
