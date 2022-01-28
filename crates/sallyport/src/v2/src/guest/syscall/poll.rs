// SPDX-License-Identifier: Apache-2.0

use super::types::Argv;
use crate::guest::alloc::{Allocator, Collector, Output, Syscall};
use crate::Result;

use libc::{c_int, c_long, pollfd};

pub struct Poll<'a> {
    pub fds: &'a mut [pollfd],
    pub timeout: c_int,
}

unsafe impl<'a> Syscall<'a> for Poll<'a> {
    const NUM: c_long = libc::SYS_poll;

    type Argv = Argv<3>;
    type Ret = c_int;

    type Staged = Output<'a, [pollfd], &'a mut [pollfd]>;
    type Committed = Self::Staged;
    type Collected = Option<Result<c_int>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let fds = Output::stage_slice(alloc, self.fds)?;
        Ok((Argv([fds.offset(), fds.len(), self.timeout as _]), fds))
    }

    fn collect(
        fds: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret as usize > fds.len() => None,
            res @ Ok(ret) => {
                unsafe { fds.collect_range(col, 0..ret as _) };
                Some(res)
            }
            err => Some(err),
        }
    }
}
