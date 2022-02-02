// SPDX-License-Identifier: Apache-2.0

use super::types::{Argv, SockaddrInput, StagedBytesInput};
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Input, Stage};
use crate::Result;

use libc::{c_int, c_long, size_t};

pub struct Sendto<'a, T> {
    pub sockfd: c_int,
    pub buf: &'a [u8],
    pub flags: c_int,
    pub dest_addr: T,
}

unsafe impl<'a, T: Into<SockaddrInput<'a>>> Alloc<'a> for Sendto<'a, T> {
    const NUM: c_long = libc::SYS_sendto;

    type Argv = Argv<6>;
    type Ret = size_t;

    type Staged = StagedBytesInput<'a>;
    type Committed = size_t;
    type Collected = Option<Result<size_t>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let dest_addr = self.dest_addr.into().stage(alloc)?;
        let (buf, _) = Input::stage_slice_max(alloc, self.buf)?;
        Ok((
            Argv([
                self.sockfd as _,
                buf.offset(),
                buf.len(),
                self.flags as _,
                dest_addr.offset(),
                dest_addr.len(),
            ]),
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
