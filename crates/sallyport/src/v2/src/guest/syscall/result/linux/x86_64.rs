// SPDX-License-Identifier: Apache-2.0

use core::marker::PhantomData;
use libc::c_int;

pub const MAX_ERRNO: c_int = 4096;
pub const ERRNO_START: usize = usize::MAX - MAX_ERRNO as usize;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(transparent)]
pub struct Result<T>([usize; 2], PhantomData<T>);

impl<T> Result<T> {
    #[inline]
    pub const unsafe fn errno_unchecked(errno: c_int) -> Self {
        Self([-errno as usize, 0], PhantomData)
    }

    #[inline]
    pub const fn errno(errno: c_int) -> Option<Self> {
        match errno {
            0..=MAX_ERRNO => Some(unsafe { Self::errno_unchecked(errno) }),
            _ => None,
        }
    }
}

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

    #[test]
    fn result() {
        const ERRNO: c_int = libc::EPERM;

        let expected: Result<isize> = unsafe { super::Result::errno_unchecked(ERRNO) };
        assert_eq!(
            Result::from([unsafe { libc::fcntl(-1, libc::F_GETFD) } as usize, 0]),
            expected
        );

        let res: crate::Result<_> = expected.into();
        assert_eq!(res, Err(ERRNO));
    }
}
