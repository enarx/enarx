// SPDX-License-Identifier: Apache-2.0

//! A WasiFile behaving like `/dev/null`

use std::any::Any;

use wasi_common::file::{FdFlags, FileType};
use wasi_common::{Error, WasiFile};

pub struct Null;

#[wiggle::async_trait]
impl WasiFile for Null {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn get_filetype(&self) -> Result<FileType, Error> {
        Ok(FileType::Pipe)
    }

    async fn get_fdflags(&self) -> Result<FdFlags, Error> {
        Ok(FdFlags::APPEND | FdFlags::NONBLOCK)
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

    async fn peek(&self, _buf: &mut [u8]) -> Result<u64, Error> {
        Ok(0)
    }

    async fn readable(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn writable(&self) -> Result<(), Error> {
        Ok(())
    }
}
