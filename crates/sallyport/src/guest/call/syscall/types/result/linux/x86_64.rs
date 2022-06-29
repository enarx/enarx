// SPDX-License-Identifier: Apache-2.0

use crate::libc::EOVERFLOW;

use core::ffi::c_int;
use core::marker::PhantomData;

pub const MAX_ERRNO: c_int = 4096;
pub const ERRNO_START: usize = usize::MAX - MAX_ERRNO as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Result<T>([usize; 2], PhantomData<T>);

impl<T> From<Result<T>> for [usize; 2] {
    #[inline]
    fn from(res: Result<T>) -> Self {
        res.0
    }
}

impl<T> From<[usize; 2]> for Result<T> {
    #[inline]
    fn from(ret: [usize; 2]) -> Self {
        Self(ret, PhantomData)
    }
}

impl From<Result<()>> for crate::Result<()> {
    #[inline]
    fn from(res: Result<()>) -> Self {
        match res.0 {
            [errno @ ERRNO_START..=usize::MAX, _] => Err(-(errno as c_int)),
            _ => Ok(()),
        }
    }
}

impl From<Result<c_int>> for crate::Result<c_int> {
    #[inline]
    fn from(res: Result<c_int>) -> Self {
        match res.0 {
            [errno @ ERRNO_START..=usize::MAX, _] => Err(-(errno as c_int)),
            [ret, _] if ret <= c_int::MAX as usize => Ok(ret as c_int),
            _ => Err(EOVERFLOW),
        }
    }
}

impl From<Result<usize>> for crate::Result<usize> {
    #[inline]
    fn from(res: Result<usize>) -> Self {
        match res.0 {
            [errno @ ERRNO_START..=usize::MAX, _] => Err(-(errno as c_int)),
            [ret, _] => Ok(ret),
        }
    }
}

impl From<Result<isize>> for crate::Result<usize> {
    #[inline]
    fn from(res: Result<isize>) -> Self {
        Result::<usize>(res.0, PhantomData).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::{self, EPERM, F_GETFD};

    #[test]
    fn result() {
        const ERRNO: c_int = EPERM;

        let expected: Result<isize> = [-ERRNO as usize, 0].into();
        assert_eq!(
            Result::from([unsafe { libc::fcntl(-1, F_GETFD) } as usize, 0]),
            expected
        );

        let res: crate::Result<_> = expected.into();
        assert_eq!(res, Err(ERRNO));
    }
}
