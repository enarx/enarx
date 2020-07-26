// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::convert::TryInto;
use std::path::{Component, Path};
use wasi_common::virtfs::{FileContents, VirtualDirEntry};
use wasi_common::wasi::{types, Result};

/// Copied from wasi-common/src/virtfs.rs.
pub struct VecFileContents {
    content: Vec<u8>,
}

impl VecFileContents {
    pub fn new(content: Vec<u8>) -> Self {
        Self { content }
    }
}

impl FileContents for VecFileContents {
    fn max_size(&self) -> types::Filesize {
        std::usize::MAX as types::Filesize
    }

    fn size(&self) -> types::Filesize {
        self.content.len() as types::Filesize
    }

    fn resize(&mut self, _new_size: types::Filesize) -> Result<()> {
        Err(types::Errno::Inval)
    }

    fn preadv(&self, iovs: &mut [std::io::IoSliceMut], offset: types::Filesize) -> Result<usize> {
        let mut read_total = 0usize;
        for iov in iovs.iter_mut() {
            let read = self.pread(iov, offset + read_total as types::Filesize)?;
            read_total = read_total.checked_add(read).expect("FileContents::preadv must not be called when reads could total to more bytes than the return value can hold");
        }
        Ok(read_total)
    }

    fn pwritev(&mut self, _iovs: &[std::io::IoSlice], _offset: types::Filesize) -> Result<usize> {
        Err(types::Errno::Inval)
    }

    fn pread(&self, buf: &mut [u8], offset: types::Filesize) -> Result<usize> {
        let offset: usize = offset.try_into().map_err(|_| types::Errno::Inval)?;

        let data_remaining = self.content.len().saturating_sub(offset);

        let read_count = std::cmp::min(buf.len(), data_remaining);

        (&mut buf[..read_count]).copy_from_slice(&self.content[offset..][..read_count]);
        Ok(read_count)
    }

    fn pwrite(&mut self, _buf: &[u8], _offset: types::Filesize) -> Result<usize> {
        Err(types::Errno::Inval)
    }
}

pub fn populate_directory(
    mut dir: &mut VirtualDirEntry,
    path: impl AsRef<Path>,
) -> Result<&mut VirtualDirEntry> {
    for component in path.as_ref().components() {
        let name = match component {
            Component::Normal(first) => first.to_str().unwrap().to_string(),
            _ => return Err(types::Errno::Inval),
        };
        match dir {
            VirtualDirEntry::Directory(ref mut map) => {
                if !map.contains_key(&name) {
                    map.insert(name.clone(), VirtualDirEntry::Directory(HashMap::new()));
                }
                dir = map.get_mut(&name).unwrap();
            }
            _ => unreachable!(),
        }
    }
    Ok(dir)
}
