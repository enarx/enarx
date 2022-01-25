// SPDX-License-Identifier: Apache-2.0

use super::Argv;
use crate::guest::alloc::{Allocator, Collector, Input, Syscall};
use crate::Result;

use libc::{c_int, c_long};

pub struct Setsockopt<'a> {
    pub sockfd: c_int,
    pub level: c_int,
    pub optname: c_int,
    pub optval: &'a [u8],
}

unsafe impl<'a> Syscall<'a> for Setsockopt<'a> {
    const NUM: c_long = libc::SYS_setsockopt;

    type Argv = Argv<5>;
    type Ret = c_int;

    type Staged = ();
    type Committed = ();
    type Collected = Result<c_int>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let optval = Input::stage_slice(alloc, self.optval)?;
        Ok((
            Argv([
                self.sockfd as _,
                self.level as _,
                self.optname as _,
                optval.offset(),
                optval.len(),
            ]),
            (),
        ))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
