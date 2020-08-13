// SPDX-License-Identifier: Apache-2.0

use bounds::Span;

use std::fs::File;
use std::io::{Error, Result};
use std::os::unix::io::AsRawFd;

/// Calls `munmap()` when going out of scope
///
/// This simple type just tracks the lifespan of a region of memory.
#[repr(transparent)]
pub struct Unmap(Span<usize, usize>);

impl Unmap {
    /// Create a new Unmap from a `Span`
    ///
    /// # Safety
    ///
    /// The caller has to ensure, that nothing else uses the memory region,
    /// if the `Unmap` object is dropped.
    pub unsafe fn new(span: Span<usize, usize>) -> Self {
        Self(span)
    }

    /// Return the inner Span
    pub fn span(&self) -> Span<usize, usize> {
        self.0
    }
}

impl Drop for Unmap {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0.start as *mut _, self.0.count) };
    }
}

/// mmap a memory region
///
/// # Safety
///
/// This is a hint, that any usage of the memory region mapped is unsafe.
pub unsafe fn map(
    addr: usize,
    len: usize,
    prot: libc::c_int,
    flags: libc::c_int,
    file: Option<&File>,
    offset: usize,
) -> Result<usize> {
    let fd = file.map(|x| x.as_raw_fd()).unwrap_or(-1);
    let ret = libc::mmap(addr as _, len, prot, flags, fd, offset as _);
    if ret == libc::MAP_FAILED {
        return Err(Error::last_os_error());
    }

    Ok(ret as _)
}
