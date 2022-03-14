// SPDX-License-Identifier: Apache-2.0

use crate::libc::c_int;

use core::marker::PhantomData;

pub const MAX_ERRNO: c_int = 4096;
pub const ERRNO_START: usize = usize::MAX - MAX_ERRNO as usize;

#[derive(Clone, Copy, Debug, PartialEq)]
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
            errno @ ERRNO_START..=usize::MAX => Err(-(errno as c_int)),
            _ => Ok(()),
        }
    }
}

impl From<Result<usize>> for crate::Result<usize> {
    #[inline]
    fn from(res: Result<usize>) -> Self {
        match res.0 {
            errno @ ERRNO_START..=usize::MAX => Err(-(errno as c_int)),
            ret => Ok(ret),
        }
    }
}
