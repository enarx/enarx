// SPDX-License-Identifier: Apache-2.0

pub mod enarxcall;
pub mod syscall;

use core::slice;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::ptr::NonNull;
use std::thread;

use libc::{c_int, c_ulong, c_void, off_t, size_t, EINVAL, ENOSYS};
use sallyport::guest::{Handler, Platform, ThreadLocalStorage};
use sallyport::item::Block;
use sallyport::util::ptr;
use sallyport::{host, Result};

pub struct TestHandler<const N: usize> {
    block: [usize; N],
    tls: ThreadLocalStorage,
}

pub struct TestPlatform;

impl Platform for TestPlatform {
    #[inline]
    fn validate_mut<T>(&self, ptr: usize) -> Result<&mut T> {
        ptr::is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;
        // unsound for testing
        unsafe { (ptr as *mut T).as_mut().ok_or(EINVAL) }
    }

    #[inline]
    fn validate<T>(&self, ptr: usize) -> Result<&T> {
        ptr::is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;
        // unsound for testing
        unsafe { (ptr as *const T).as_ref().ok_or(EINVAL) }
    }

    #[inline]
    fn validate_slice_mut<T: Sized>(&self, ptr: usize, count: usize) -> Result<&mut [T]> {
        ptr::is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;
        // unsound for testing
        unsafe { Ok(slice::from_raw_parts_mut(ptr as *mut T, count)) }
    }

    #[inline]
    fn validate_slice<T: Sized>(&self, ptr: usize, count: usize) -> Result<&[T]> {
        ptr::is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;
        // unsound for testing
        unsafe { Ok(slice::from_raw_parts(ptr as *const T, count)) }
    }
}

impl<const N: usize> Handler for TestHandler<N> {
    fn sally(&mut self) -> Result<()> {
        host::execute(Block::from(self.block_mut()))
    }

    fn block(&self) -> &[usize] {
        self.block.as_slice()
    }

    fn block_mut(&mut self) -> &mut [usize] {
        self.block.as_mut_slice()
    }

    fn thread_local_storage(&mut self) -> &mut ThreadLocalStorage {
        &mut self.tls
    }

    fn arch_prctl(
        &mut self,
        _platform: &impl Platform,
        _code: c_int,
        _addr: c_ulong,
    ) -> Result<()> {
        Err(ENOSYS)
    }

    fn brk(
        &mut self,
        _platform: &impl Platform,
        _addr: Option<NonNull<c_void>>,
    ) -> Result<NonNull<c_void>> {
        Err(ENOSYS)
    }

    fn madvise(
        &mut self,
        _platform: &impl Platform,
        _addr: NonNull<c_void>,
        _length: size_t,
        _advice: c_int,
    ) -> Result<()> {
        Err(ENOSYS)
    }

    fn mmap(
        &mut self,
        _platform: &impl Platform,
        _addr: Option<NonNull<c_void>>,
        _length: size_t,
        _prot: c_int,
        _flags: c_int,
        _fd: c_int,
        _offset: off_t,
    ) -> Result<NonNull<c_void>> {
        Err(ENOSYS)
    }

    fn mprotect(
        &mut self,
        _platform: &impl Platform,
        _addr: NonNull<c_void>,
        _len: size_t,
        _prot: c_int,
    ) -> Result<()> {
        Err(ENOSYS)
    }

    fn munmap(
        &mut self,
        _platform: &impl Platform,
        _addr: NonNull<c_void>,
        _length: size_t,
    ) -> Result<()> {
        Err(ENOSYS)
    }
}

pub fn run_test<const N: usize, F>(iterations: usize, block: [usize; N], f: F)
where
    F: FnOnce(usize, &mut TestPlatform, &mut TestHandler<N>) + Sync + Send + Copy + 'static,
{
    for i in 0..iterations {
        thread::Builder::new()
            .name(format!("iteration {}", i))
            .spawn(move || {
                let mut platform = TestPlatform;
                let mut handler = TestHandler {
                    block: block.clone(),
                    tls: Default::default(),
                };
                f(i, &mut platform, &mut handler);
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
