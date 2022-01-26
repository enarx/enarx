// SPDX-License-Identifier: Apache-2.0

use super::types::{Argv, CommittedSockaddrOutput, SockaddrOutput, StagedSockaddrOutput};
use crate::guest::alloc::{Allocator, Collect, Collector, Stage, Syscall};
use crate::Result;

use libc::{c_int, c_long};

pub struct Getsockname<'a> {
    pub sockfd: c_int,
    pub addr: SockaddrOutput<'a>,
}

unsafe impl<'a> Syscall<'a> for Getsockname<'a> {
    const NUM: c_long = libc::SYS_getsockname;

    type Argv = Argv<3>;
    type Ret = ();

    type Staged = StagedSockaddrOutput<'a>;
    type Committed = CommittedSockaddrOutput<'a>;
    type Collected = Result<()>;

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let addr = self.addr.stage(alloc)?;
        Ok((
            Argv([self.sockfd as _, addr.addr.offset(), addr.addrlen.offset()]),
            addr,
        ))
    }

    #[inline]
    fn collect(
        addr: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        addr.collect(col);
        ret
    }
}
