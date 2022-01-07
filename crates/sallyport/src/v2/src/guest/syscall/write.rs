// SPDX-License-Identifier: Apache-2.0

use super::Argv;
use crate::guest::alloc::{Allocator, Collector, Commit, Input, Syscall};
use crate::Result;

use libc::{c_int, c_long, size_t};

pub struct Write<'a> {
    pub fd: c_int,
    pub buf: &'a [u8],
}

pub struct StagedWrite<'a>(Input<'a, [u8], &'a [u8]>);

impl<'a> Commit for StagedWrite<'a> {
    type Item = size_t;

    fn commit(self, com: &impl crate::guest::alloc::Committer) -> Self::Item {
        let len = self.0.len();
        self.0.commit(com);
        len
    }
}

unsafe impl<'a> Syscall<'a> for Write<'a> {
    const NUM: c_long = libc::SYS_write;

    type Argv = Argv<3>;
    type Ret = size_t;

    type Staged = StagedWrite<'a>;
    type Committed = size_t;
    type Collected = Option<Result<size_t>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let (buf, _) = Input::stage_slice_max(alloc, self.buf)?;
        Ok((
            Argv([self.fd as _, buf.offset(), buf.len()]),
            StagedWrite(buf),
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
