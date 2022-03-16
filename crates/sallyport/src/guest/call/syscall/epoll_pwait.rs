// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Commit, Committer, Input, Output};
use crate::libc::{epoll_event, sigset_t, SYS_epoll_pwait};
use crate::Result;

use core::ffi::{c_int, c_long};

pub struct EpollPwait<'a> {
    pub epfd: c_int,
    pub events: &'a mut [epoll_event],
    pub timeout: c_int,
    pub sigmask: &'a sigset_t,
}

pub struct StagedEpollPwait<'a> {
    events: Output<'a, [epoll_event], &'a mut [epoll_event]>,
    sigmask: Input<'a, sigset_t, &'a sigset_t>,
}

impl<'a> Commit for StagedEpollPwait<'a> {
    type Item = Output<'a, [epoll_event], &'a mut [epoll_event]>;

    fn commit(self, com: &impl Committer) -> Self::Item {
        let events = self.events.commit(com);
        self.sigmask.commit(com);
        events
    }
}

unsafe impl<'a> Alloc<'a> for EpollPwait<'a> {
    const NUM: c_long = SYS_epoll_pwait;

    type Argv = Argv<5>;
    type Ret = c_int;

    type Staged = StagedEpollPwait<'a>;
    type Committed = Output<'a, [epoll_event], &'a mut [epoll_event]>;
    type Collected = Option<Result<c_int>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let events = Output::stage_slice(alloc, self.events)?;
        let sigmask = Input::stage(alloc, self.sigmask)?;
        Ok((
            Argv([
                self.epfd as _,
                events.offset(),
                events.len(),
                self.timeout as _,
                sigmask.offset(),
            ]),
            Self::Staged { events, sigmask },
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
