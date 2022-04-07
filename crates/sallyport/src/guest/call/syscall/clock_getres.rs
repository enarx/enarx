// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collect, Collector, Output};
use crate::libc::{clockid_t, timespec, SYS_clock_getres};
use crate::{Result, NULL};

use core::ffi::c_long;

pub struct ClockGetres<'a> {
    pub clockid: clockid_t,
    pub res: Option<&'a mut timespec>,
}

unsafe impl<'a> Alloc<'a> for ClockGetres<'a> {
    const NUM: c_long = SYS_clock_getres;

    type Argv = Argv<2>;
    type Ret = ();

    type Staged = Option<Output<'a, timespec, &'a mut timespec>>;
    type Committed = Self::Staged;
    type Collected = Result<()>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let (res, res_offset) = if let Some(res) = self.res {
            let res = Output::stage(alloc, res)?;
            let res_offset = res.offset();
            (Some(res), res_offset)
        } else {
            (None, NULL)
        };
        Ok((Argv([self.clockid as _, res_offset]), res))
    }

    fn collect(
        res: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        if ret.is_ok() {
            res.collect(col);
        };
        ret
    }
}
