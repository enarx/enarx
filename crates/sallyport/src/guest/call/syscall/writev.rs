// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::{iov_len, Alloc};
use crate::guest::alloc::{Allocator, Collector, Commit, Committer, InRef};
use crate::libc::SYS_write;
use crate::Result;

use core::ffi::{c_int, c_long, c_size_t};

pub struct Writev<T> {
    pub fd: c_int,
    pub iovs: T,
}

pub struct StagedWritev<'a, T> {
    buf: InRef<'a, [u8]>,
    iovs: T,
}

impl<'a, T, U> Commit for StagedWritev<'a, &'a T>
where
    T: ?Sized,
    for<'b> &'b T: IntoIterator<Item = &'b U>,
    U: AsRef<[u8]>,
{
    type Item = c_size_t;

    fn commit(mut self, com: &impl Committer) -> Self::Item {
        let mut capacity = self.buf.len();
        unsafe {
            self.buf.copy_from_iter_unchecked(
                com,
                self.iovs.into_iter().map_while(|iov| {
                    if capacity == 0 {
                        return None;
                    }
                    let iov = iov.as_ref();
                    let len = iov.len();
                    if len <= capacity {
                        capacity -= len;
                        Some(iov)
                    } else {
                        let mid = capacity;
                        capacity = 0;
                        Some(iov.split_at(mid).0)
                    }
                }),
            );
        }
        self.buf.len()
    }
}

unsafe impl<'a, T, U> Alloc<'a> for Writev<&'a T>
where
    T: ?Sized,
    for<'b> &'b T: IntoIterator<Item = &'b U>,
    U: AsRef<[u8]>,
{
    const NUM: c_long = SYS_write;

    type Argv = Argv<3>;
    type Ret = c_size_t;

    type Staged = StagedWritev<'a, &'a T>;
    type Committed = c_size_t;
    type Collected = Option<Result<c_size_t>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let buf = alloc.allocate_input_slice_max(iov_len(self.iovs))?;
        Ok((
            Argv([self.fd as _, buf.offset(), buf.len()]),
            StagedWritev {
                iovs: self.iovs,
                buf,
            },
        ))
    }

    fn collect(
        count: Self::Committed,
        ret: Result<Self::Ret>,
        _: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret > count => None,
            res @ Ok(_) => Some(res),
            err => Some(err),
        }
    }
}
