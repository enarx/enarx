// SPDX-License-Identifier: Apache-2.0

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

impl From<Result<c_int>> for crate::Result<c_int> {
    #[inline]
    fn from(res: Result<c_int>) -> Self {
        match res.0 {
            errno @ ERRNO_START.. => Err(-(errno as c_int)),
            ret => Ok(ret as _),
        }
    }
}
