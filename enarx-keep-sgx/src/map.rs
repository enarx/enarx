// SPDX-License-Identifier: Apache-2.0

use span::Span;

use std::fs::File;
use std::io::{Error, Result};
use std::os::unix::io::AsRawFd;

// FIXME: https://github.com/rust-lang/libc/pull/1658
pub const MAP_SYNC: libc::c_int = libc::MAP_HUGETLB << 1;
pub const MAP_FIXED_NOREPLACE: libc::c_int = MAP_SYNC << 1;

/// Calls `munmap()` when going out of scope
///
/// This simple type just tracks the lifespan of a region of memory.
#[repr(transparent)]
pub struct Unmap(Span<usize, usize>);

impl Unmap {
    pub unsafe fn new(span: Span<usize, usize>) -> Self {
        Self(span)
    }

    pub fn span(&self) -> Span<usize, usize> {
        self.0
    }
}

impl Drop for Unmap {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0.start as *mut _, self.0.count) };
    }
}

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
