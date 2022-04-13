// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::types::{CommittedSockaddrOutput, SockaddrOutput, StagedSockaddrOutput};
use super::Alloc;
use crate::guest::alloc::{Allocator, Collect, Collector, Stage};
use crate::libc::SYS_getsockname;
use crate::Result;

use core::ffi::{c_int, c_long};

pub struct Getsockname<T> {
    pub sockfd: c_int,
    pub addr: T,
}

unsafe impl<'a, T: Into<SockaddrOutput<'a>>> Alloc<'a> for Getsockname<T> {
    const NUM: c_long = SYS_getsockname;

    type Argv = Argv<3>;
    type Ret = ();

    type Staged = StagedSockaddrOutput<'a>;
    type Committed = CommittedSockaddrOutput<'a>;
    type Collected = Result<()>;

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let addr = self.addr.into().stage(alloc)?;
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
