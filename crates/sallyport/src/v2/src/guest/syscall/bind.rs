// SPDX-License-Identifier: Apache-2.0

use super::Argv;
use crate::guest::alloc::{Allocator, Collector, Input, Syscall};
use crate::Result;

use libc::{c_int, c_long};

pub struct Bind<'a> {
    pub sockfd: c_int,
    pub addr: &'a [u8],
}

unsafe impl<'a> Syscall<'a> for Bind<'a> {
    const NUM: c_long = libc::SYS_bind;

    type Argv = Argv<3>;
    type Ret = ();

    type Staged = Input<'a, [u8], &'a [u8]>;
    type Committed = ();
    type Collected = Result<()>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let addr = Input::stage_slice(alloc, self.addr)?;
        Ok((Argv([self.sockfd as _, addr.offset(), addr.len()]), addr))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
