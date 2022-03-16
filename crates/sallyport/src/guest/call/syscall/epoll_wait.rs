// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Output};
use crate::libc::{epoll_event, SYS_epoll_wait};
use crate::Result;

use core::ffi::{c_int, c_long};

pub struct EpollWait<'a> {
    pub epfd: c_int,
    pub events: &'a mut [epoll_event],
    pub timeout: c_int,
}

unsafe impl<'a> Alloc<'a> for EpollWait<'a> {
    const NUM: c_long = SYS_epoll_wait;

    type Argv = Argv<4>;
    type Ret = c_int;

    type Staged = Output<'a, [epoll_event], &'a mut [epoll_event]>;
    type Committed = Self::Staged;
    type Collected = Option<Result<c_int>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let events = Output::stage_slice(alloc, self.events)?;
        Ok((
            Argv([
                self.epfd as _,
                events.offset(),
                events.len(),
                self.timeout as _,
            ]),
            events,
        ))
    }

    fn collect(
        events: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret as usize > events.len() => None,
            res @ Ok(ret) => {
                unsafe { events.collect_range(col, 0..ret as _) };
                Some(res)
            }
            err => Some(err),
        }
    }
}
