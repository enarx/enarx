// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::types::{SockoptInput, StagedSockoptInput};
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Commit, Committer, Stage};
use crate::libc::SYS_setsockopt;
use crate::{Result, NULL};

use core::ffi::{c_int, c_long};

pub struct Setsockopt<T> {
    pub sockfd: c_int,
    pub level: c_int,
    pub optname: c_int,
    pub optval: Option<T>,
}

pub struct StagedSetsockopt<'a> {
    optval: Option<StagedSockoptInput<'a>>,
}

impl<'a> Commit for StagedSetsockopt<'a> {
    type Item = ();

    fn commit(self, com: &impl Committer) -> Self::Item {
        self.optval.commit(com);
    }
}

unsafe impl<'a, T: Into<SockoptInput<'a>>> Alloc<'a> for Setsockopt<T> {
    const NUM: c_long = SYS_setsockopt;

    type Argv = Argv<5>;
    type Ret = c_int;

    type Staged = StagedSetsockopt<'a>;
    type Committed = ();
    type Collected = Result<c_int>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let optval = self
            .optval
            .map(Into::into)
            .map(|optval| optval.stage(alloc))
            .transpose()?;
        let (optval_offset, optlen) = optval
            .as_ref()
            .map_or((NULL, 0), |optval| (optval.offset(), optval.len()));

        Ok((
            Argv([
                self.sockfd as _,
                self.level as _,
                self.optname as _,
                optval_offset,
                optlen,
            ]),
            StagedSetsockopt { optval },
        ))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
