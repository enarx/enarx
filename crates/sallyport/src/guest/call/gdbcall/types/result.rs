// SPDX-License-Identifier: Apache-2.0

use crate::libc::EOVERFLOW;
use crate::NULL;

use core::ffi::c_int;
use core::marker::PhantomData;

pub const MAX_ERRNO: c_int = 4096;
pub const ERRNO_START: usize = usize::MAX - MAX_ERRNO as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Result<T>(usize, PhantomData<T>);

impl<T> From<Result<T>> for usize {
    #[inline]
    fn from(res: Result<T>) -> Self {
        res.0
    }
}

impl<T> From<usize> for Result<T> {
    #[inline]
    fn from(ret: usize) -> Self {
        Self(ret, PhantomData)
    }
}

impl From<Result<()>> for crate::Result<()> {
    #[inline]
    fn from(res: Result<()>) -> Self {
        match res.0 {
            errno @ ERRNO_START.. => Err(-(errno as c_int)),
            _ => Ok(()),
        }
    }
}

impl From<Result<usize>> for crate::Result<usize> {
    #[inline]
    fn from(res: Result<usize>) -> Self {
        match res.0 {
            errno @ ERRNO_START.. => Err(-(errno as c_int)),
            ret => Ok(ret),
        }
    }
}

impl From<Result<u8>> for crate::Result<u8> {
    #[inline]
    fn from(res: Result<u8>) -> Self {
        match res.0 {
            errno @ ERRNO_START.. => Err(-(errno as c_int)),
            ret if ret <= u8::MAX as _ => Ok(ret as _),
            _ => Err(EOVERFLOW),
        }
    }
}

impl From<Result<Option<u8>>> for crate::Result<Option<u8>> {
    #[inline]
    fn from(res: Result<Option<u8>>) -> Self {
        match res.0 {
            NULL => Ok(None),
            ret if ret >= ERRNO_START => Err(-(ret as c_int)),
            ret if ret <= u8::MAX as _ => Ok(Some(ret as _)),
            _ => Err(EOVERFLOW),
        }
    }
}
