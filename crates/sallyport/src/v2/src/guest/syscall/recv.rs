// SPDX-License-Identifier: Apache-2.0

use super::types::Argv;
use crate::guest::alloc::{Allocator, Collector, Output, Syscall};
use crate::Result;

use libc::{c_int, c_long, size_t};

pub struct Recv<'a> {
    pub sockfd: c_int,
    pub buf: &'a mut [u8],
    pub flags: c_int,
}

unsafe impl<'a> Syscall<'a> for Recv<'a> {
    const NUM: c_long = libc::SYS_recvfrom;

    type Argv = Argv<4>;
    type Ret = size_t;

    type Staged = Output<'a, [u8], &'a mut [u8]>;
    type Committed = Self::Staged;
    type Collected = Option<Result<size_t>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let (buf, _) = Output::stage_slice_max(alloc, self.buf)?;
        Ok((
            Argv([self.sockfd as _, buf.offset(), buf.len(), self.flags as _]),
            buf,
        ))
    }

    fn collect(
        buf: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret > buf.len() => None,
            res @ Ok(ret) => {
                unsafe { buf.collect_range(col, 0..ret) };
                Some(res)
            }
            err => Some(err),
        }
    }
}
