// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Input};
use crate::libc::{epoll_event, SYS_epoll_ctl};
use crate::Result;

use core::ffi::{c_int, c_long};

pub struct EpollCtl<'a> {
    pub epfd: c_int,
    pub op: c_int,
    pub fd: c_int,
    pub event: &'a epoll_event,
}

unsafe impl<'a> Alloc<'a> for EpollCtl<'a> {
    const NUM: c_long = SYS_epoll_ctl;

    type Argv = Argv<4>;
    type Ret = ();

    type Staged = Input<'a, epoll_event, &'a epoll_event>;
    type Committed = ();
    type Collected = Result<()>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let event = Input::stage(alloc, self.event)?;
        Ok((
            Argv([self.epfd as _, self.op as _, self.fd as _, event.offset()]),
            event,
        ))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
