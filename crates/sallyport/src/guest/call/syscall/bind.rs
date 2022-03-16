// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::types::{SockaddrInput, StagedSockaddrInput};
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Stage};
use crate::libc::SYS_bind;
use crate::Result;

use core::ffi::{c_int, c_long};

pub struct Bind<T> {
    pub sockfd: c_int,
    pub addr: T,
}

unsafe impl<'a, T: Into<SockaddrInput<'a>>> Alloc<'a> for Bind<T> {
    const NUM: c_long = SYS_bind;

    type Argv = Argv<3>;
    type Ret = ();

    type Staged = StagedSockaddrInput<'a>;
    type Committed = ();
    type Collected = Result<()>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let addr = self.addr.into().stage(alloc)?;
        Ok((Argv([self.sockfd as _, addr.offset(), addr.len()]), addr))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
