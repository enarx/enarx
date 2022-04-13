// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::{iov_len, Alloc};
use crate::guest::alloc::{Allocator, Collector, CommitPassthrough, OutRef};
use crate::libc::SYS_read;
use crate::Result;

use core::ffi::{c_int, c_long, c_size_t};

pub struct Readv<T> {
    pub fd: c_int,
    pub iovs: T,
}

pub struct StagedReadv<'a, T> {
    buf: OutRef<'a, [u8]>,
    iovs: T,
}

impl<T> CommitPassthrough for StagedReadv<'_, T> {}

unsafe impl<'a, T: ?Sized, U, V> Alloc<'a> for Readv<&'a mut T>
where
    for<'b> &'b T: IntoIterator<Item = &'b U>,
    for<'b> &'b mut T: IntoIterator<Item = &'b mut V>,
    U: AsRef<[u8]>,
    V: AsMut<[u8]>,
{
    const NUM: c_long = SYS_read;

    type Argv = Argv<3>;
    type Ret = c_size_t;

    type Staged = StagedReadv<'a, &'a mut T>;
    type Committed = Self::Staged;
    type Collected = Option<Result<c_size_t>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let buf = alloc.allocate_output_slice_max(iov_len(self.iovs as &T))?;
        Ok((
            Argv([self.fd as _, buf.offset(), buf.len()]),
            StagedReadv {
                iovs: self.iovs,
                buf,
            },
        ))
    }

    fn collect(
        Self::Committed { iovs, buf }: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        #[inline]
        fn collect_iovs<'a, T, V>(
            col: &impl Collector,
            iovs: &'a mut T,
            buf: OutRef<'a, [u8]>,
            mut capacity: usize,
        ) where
            for<'b> &'b mut T: IntoIterator<Item = &'b mut V>,
            T: ?Sized,
            V: AsMut<[u8]>,
        {
            unsafe {
                buf.copy_to_iter_unchecked(
                    col,
                    iovs.into_iter().map_while(|iov| {
                        if capacity == 0 {
                            return None;
                        }
                        let iov = iov.as_mut();
                        let len = iov.len();
                        if len <= capacity {
                            capacity -= len;
                            Some(iov)
                        } else {
                            let mid = capacity;
                            capacity = 0;
                            Some(iov.split_at_mut(mid).0)
                        }
                    }),
                )
            }
        }

        match ret {
            Ok(ret) if ret > buf.len() => None,
            res @ Ok(ret) => {
                collect_iovs(col, iovs, buf, ret);
                Some(res)
            }
            err => Some(err),
        }
    }
}
