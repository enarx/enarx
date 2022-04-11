// SPDX-License-Identifier: Apache-2.0
//! A WasiFile behaving like `/dev/null`

use std::any::Any;

use wasi_common::file::{Advice, FdFlags, FileType, Filestat};
use wasi_common::{Error, ErrorExt, WasiFile};

pub struct Null;

#[wiggle::async_trait]
impl WasiFile for Null {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn sock_accept(&mut self, _fdflags: FdFlags) -> Result<Box<dyn WasiFile>, Error> {
        Err(Error::badf())
    }

    async fn datasync(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn get_filetype(&self) -> Result<FileType, Error> {
        Ok(FileType::Pipe)
    }

    async fn get_fdflags(&self) -> Result<FdFlags, Error> {
        Ok(FdFlags::APPEND | FdFlags::NONBLOCK)
    }

    async fn set_fdflags(&mut self, _fdflags: FdFlags) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn get_filestat(&self) -> Result<Filestat, Error> {
        Err(Error::badf())
    }

    async fn set_filestat_size(&self, _size: u64) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn advise(&self, _offset: u64, _len: u64, _advice: Advice) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn allocate(&self, _offset: u64, _len: u64) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn set_times(
        &self,
        _atime: Option<wasi_common::SystemTimeSpec>,
        _mtime: Option<wasi_common::SystemTimeSpec>,
    ) -> Result<(), Error> {
        Err(Error::badf())
    }

    async fn read_vectored<'a>(&self, _bufs: &mut [std::io::IoSliceMut<'a>]) -> Result<u64, Error> {
        Ok(0)
    }

    async fn read_vectored_at<'a>(
        &self,
        _bufs: &mut [std::io::IoSliceMut<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Ok(0)
    }

    async fn write_vectored<'a>(&self, bufs: &[std::io::IoSlice<'a>]) -> Result<u64, Error> {
        Ok(bufs.iter().map(|b| b.len()).sum::<usize>() as _)
    }

    async fn write_vectored_at<'a>(
        &self,
        bufs: &[std::io::IoSlice<'a>],
        _offset: u64,
    ) -> Result<u64, Error> {
        Ok(bufs.iter().map(|b| b.len()).sum::<usize>() as _)
    }

    async fn seek(&self, _pos: std::io::SeekFrom) -> Result<u64, Error> {
        Err(Error::badf())
    }

    async fn peek(&self, _buf: &mut [u8]) -> Result<u64, Error> {
        Ok(0)
    }

    async fn num_ready_bytes(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn isatty(&self) -> bool {
        false
    }

    async fn readable(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn writable(&self) -> Result<(), Error> {
        Ok(())
    }
}
