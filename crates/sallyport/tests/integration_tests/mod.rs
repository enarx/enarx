// SPDX-License-Identifier: Apache-2.0

pub mod enarxcall;
pub mod syscall;

use std::ffi::CStr;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::ptr::NonNull;
use std::{slice, thread};

use libc::{c_int, c_ulong, c_void, off_t, size_t, ENOSYS};
use sallyport::guest::{Handler, Platform, ThreadLocalStorage};
use sallyport::item::Block;
use sallyport::{host, Result};

pub struct TestHandler<const N: usize> {
    block: [usize; N],
    tls: ThreadLocalStorage,
}

impl<const N: usize> Platform for TestHandler<N> {
    fn sally(&mut self) -> Result<()> {
        host::execute(Block::from(self.block_mut()));
        Ok(())
    }

    fn validate<'a, T>(&self, ptr: usize) -> Result<&'a T> {
        Ok(unsafe { &*(ptr as *const _) })
    }

    fn validate_mut<'a, T>(&self, ptr: usize) -> Result<&'a mut T> {
        Ok(unsafe { &mut *(ptr as *mut _) })
    }

    fn validate_slice<'a, T>(&self, ptr: usize, len: usize) -> Result<&'a [T]> {
        Ok(unsafe { slice::from_raw_parts(ptr as _, len) })
    }

    fn validate_slice_mut<'a, T>(&self, ptr: usize, len: usize) -> Result<&'a mut [T]> {
        Ok(unsafe { slice::from_raw_parts_mut(ptr as _, len) })
    }

    fn validate_str<'a>(&self, ptr: usize) -> Result<&'a [u8]> {
        Ok(unsafe { CStr::from_ptr(ptr as _) }.to_bytes())
    }

    fn validate_iovec_slice_mut<'a>(
        &self,
        iov: usize,
        iovcnt: usize,
    ) -> Result<&'a mut [&'a mut [u8]]> {
        Ok(unsafe { slice::from_raw_parts_mut(iov as _, iovcnt) })
    }

    fn validate_iovec_slice<'a>(&self, iov: usize, iovcnt: usize) -> Result<&'a [&'a [u8]]> {
        Ok(unsafe { slice::from_raw_parts(iov as _, iovcnt) })
    }
}

impl<const N: usize> Handler for TestHandler<N> {
    fn block(&self) -> &[usize] {
        self.block.as_slice()
    }

    fn block_mut(&mut self) -> &mut [usize] {
        self.block.as_mut_slice()
    }

    fn thread_local_storage(&mut self) -> &mut ThreadLocalStorage {
        &mut self.tls
    }

    fn arch_prctl(&mut self, _code: c_int, _addr: c_ulong) -> Result<()> {
        Err(ENOSYS)
    }

    fn brk(&mut self, _addr: Option<NonNull<c_void>>) -> Result<NonNull<c_void>> {
        Err(ENOSYS)
    }

    fn madvise(&mut self, _addr: NonNull<c_void>, _length: size_t, _advice: c_int) -> Result<()> {
        Err(ENOSYS)
    }

    fn mmap(
        &mut self,
        _addr: Option<NonNull<c_void>>,
        _length: size_t,
        _prot: c_int,
        _flags: c_int,
        _fd: c_int,
        _offset: off_t,
    ) -> Result<NonNull<c_void>> {
        Err(ENOSYS)
    }

    fn mprotect(&mut self, _addr: NonNull<c_void>, _len: size_t, _prot: c_int) -> Result<()> {
        Err(ENOSYS)
    }

    fn munmap(&mut self, _addr: NonNull<c_void>, _length: size_t) -> Result<()> {
        Err(ENOSYS)
    }
}

pub fn run_test<const N: usize>(
    iterations: usize,
    block: [usize; N],
    f: impl FnOnce(usize, &mut TestHandler<N>) + Sync + Send + Copy + 'static,
) {
    for i in 0..iterations {
        thread::Builder::new()
            .name(format!("iteration {}", i))
            .spawn(move || {
                f(
                    i,
                    &mut TestHandler {
                        block: block.clone(),
                        tls: Default::default(),
                    },
                );
            })
            .expect(&format!("couldn't spawn test iteration {} thread", i))
            .join()
            .expect(&format!("couldn't join test iteration {} thread", i))
    }
}

pub fn write_tcp(addr: impl ToSocketAddrs, buf: &[u8]) {
    assert_eq!(
        TcpStream::connect(addr)
            .expect("couldn't connect to address")
            .write(buf)
            .expect("couldn't write data"),
        buf.len()
    );
}
