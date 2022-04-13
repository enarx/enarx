// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::types::StagedBytesInput;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Input};
use crate::libc::SYS_sendto;
use crate::Result;

use core::ffi::{c_int, c_long, c_size_t};

pub struct Send<'a> {
    pub sockfd: c_int,
    pub buf: &'a [u8],
    pub flags: c_int,
}

unsafe impl<'a> Alloc<'a> for Send<'a> {
    const NUM: c_long = SYS_sendto;

    type Argv = Argv<4>;
    type Ret = c_size_t;

    type Staged = StagedBytesInput<'a>;
    type Committed = c_size_t;
    type Collected = Option<Result<c_size_t>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let (buf, _) = Input::stage_slice_max(alloc, self.buf)?;
        Ok((
            Argv([self.sockfd as _, buf.offset(), buf.len(), self.flags as _]),
            StagedBytesInput(buf),
        ))
    }

    fn collect(
        len: Self::Committed,
        ret: Result<Self::Ret>,
        _: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret > len => None,
            res @ Ok(_) => Some(res),
            err => Some(err),
        }
    }
}
