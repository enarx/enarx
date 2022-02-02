// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::types::SockoptInput;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Stage};
use crate::{Result, NULL};

use libc::{c_int, c_long};

pub struct Setsockopt<T> {
    pub sockfd: c_int,
    pub level: c_int,
    pub optname: c_int,
    pub optval: Option<T>,
}

unsafe impl<'a, T: Into<SockoptInput<'a>>> Alloc<'a> for Setsockopt<T> {
    const NUM: c_long = libc::SYS_setsockopt;

    type Argv = Argv<5>;
    type Ret = c_int;

    type Staged = ();
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
            (),
        ))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
