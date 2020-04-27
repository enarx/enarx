// SPDX-License-Identifier: Apache-2.0

use super::map;

use memory::Page;
use span::Span;

use std::fs::File;
use std::io::{Error, Result};

#[repr(transparent)]
pub struct Contents(map::Unmap);

impl Contents {
    /// Load `span` bytes from `file` into a readable memory region of `size`
    ///
    /// Note that `size` MUST be a multiple of the page size. If the memory
    /// size is smaller than the `span` size, the data from the file will be
    /// truncated to fit into the memory region.
    pub fn from_file(size: usize, file: &File, mut span: Span<usize, usize>) -> Result<Self> {
        // Get the page size and check size alignment.
        let mask = Page::size() - 1;
        if size & mask != 0 {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        // Truncate the bytes loaded if needed.
        if size < span.count {
            span.count = size;
        }

        // Map the whole range.
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let unmap = unsafe {
            map::Unmap::new(Span {
                start: map::map(0, size, libc::PROT_READ, flags, None, 0)?,
                count: size,
            })
        };

        // Map the file data.
        if span.count > 0 {
            let flags = libc::MAP_PRIVATE | libc::MAP_FIXED;
            unsafe {
                map::map(
                    unmap.span().start,
                    span.count,
                    libc::PROT_READ,
                    flags,
                    Some(file),
                    span.start,
                )?
            };
        }

        Ok(Self(unmap))
    }
}

impl AsRef<[u8]> for Contents {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.span().start as *const u8, self.0.span().count) }
    }
}
