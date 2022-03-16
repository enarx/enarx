// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::types::{CommittedSockaddrOutput, SockaddrOutput, StagedSockaddrOutput};
use super::Alloc;
use crate::guest::alloc::{Allocator, Collect, Collector, Stage};
use crate::libc::SYS_accept;
use crate::{Result, NULL};

use core::ffi::{c_int, c_long};

pub struct Accept<T> {
    pub sockfd: c_int,
    pub addr: Option<T>,
}

unsafe impl<'a, T: Into<SockaddrOutput<'a>>> Alloc<'a> for Accept<T> {
    const NUM: c_long = SYS_accept;

    type Argv = Argv<3>;
    type Ret = c_int;

    type Staged = Option<StagedSockaddrOutput<'a>>;
    type Committed = Option<CommittedSockaddrOutput<'a>>;
    type Collected = Result<c_int>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let addr = self.addr.map(Into::into).stage(alloc)?;
        let (addr_offset, addrlen_offset) = addr
            .as_ref()
            .map_or((NULL, NULL), |StagedSockaddrOutput { addr, addrlen }| {
                (addr.offset(), addrlen.offset())
            });
        Ok((Argv([self.sockfd as _, addr_offset, addrlen_offset]), addr))
    }

    fn collect(
        addr: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        addr.collect(col);
        ret
    }
}
