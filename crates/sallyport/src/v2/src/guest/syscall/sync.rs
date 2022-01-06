// SPDX-License-Identifier: Apache-2.0

use super::Argv;
use crate::guest::alloc::{Allocator, Collector, Syscall};
use crate::Result;

use libc::c_long;

pub struct Sync;

unsafe impl<'a> Syscall<'a> for Sync {
    const NUM: c_long = libc::SYS_sync;

    type Argv = Argv<0>;
    type Ret = super::Result<()>;

    type Staged = ();
    type Committed = ();
    type Collected = Result<()>;

    fn stage(self, _: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        Ok((Argv([]), ()))
    }

    fn collect(_: Self::Committed, ret: Self::Ret, _: &impl Collector) -> Result<()> {
        ret.into()
    }
}
