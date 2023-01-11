// SPDX-License-Identifier: Apache-2.0

//! A WasiFile RNG relying on `RDRAND` instruction for generating random numbers akin to `/dev/urandom`.

use super::super::WasiResult;

use std::any::Any;
use std::arch::x86_64::{_rdrand16_step, _rdrand32_step, _rdrand64_step};
use std::io::{self, ErrorKind, Read};

use wasi_common::file::{FdFlags, FileType};
use wasi_common::{Error, WasiFile};
use wiggle::async_trait;

#[derive(Clone)]
pub struct Urandom;

impl Read for Urandom {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match buf.len() {
            0 => Some(0),
            n @ 1..=2 => {
                let mut val = 0;
                (unsafe { _rdrand16_step(&mut val) } == 1).then(|| {
                    buf[..n].copy_from_slice(&val.to_ne_bytes());
                    n
                })
            }
            n @ 3..=4 => {
                let mut val = 0;
                (unsafe { _rdrand32_step(&mut val) } == 1).then(|| {
                    buf[..n].copy_from_slice(&val.to_ne_bytes());
                    n
                })
            }
            n => {
                let mut val = 0;
                (unsafe { _rdrand64_step(&mut val) } == 1).then(|| {
                    let n = n.min(8);
                    buf[..n].copy_from_slice(&val.to_ne_bytes());
                    n
                })
            }
        }
        .ok_or_else(|| io::Error::new(ErrorKind::WouldBlock, "not enough entropy"))
    }
}

#[async_trait]
impl WasiFile for Urandom {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn get_filetype(&mut self) -> WasiResult<FileType> {
        Ok(FileType::CharacterDevice)
    }

    async fn get_fdflags(&mut self) -> WasiResult<FdFlags> {
        Ok(FdFlags::NONBLOCK)
    }

    async fn read_vectored<'a>(&mut self, bufs: &mut [io::IoSliceMut<'a>]) -> WasiResult<u64> {
        bufs.into_iter().try_fold(0, |sum, buf| {
            let n = buf.len() as u64;
            Urandom.read_exact(buf)?;
            Ok(sum + n)
        })
    }

    async fn write_vectored<'a>(&mut self, bufs: &[io::IoSlice<'a>]) -> WasiResult<u64> {
        Ok(bufs.iter().map(|b| b.len()).sum::<usize>() as _)
    }

    async fn write_vectored_at<'a>(
        &mut self,
        bufs: &[io::IoSlice<'a>],
        _offset: u64,
    ) -> WasiResult<u64> {
        Ok(bufs.iter().map(|b| b.len()).sum::<usize>() as _)
    }

    async fn readable(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn writable(&self) -> WasiResult<()> {
        Ok(())
    }
}
