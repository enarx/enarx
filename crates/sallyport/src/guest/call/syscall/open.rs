// SPDX-License-Identifier: Apache-2.0

use super::super::alloc::kind;
use super::super::types::Argv;
use super::super::{MaybeAlloc, UnstagedMaybeAlloc};
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Input};
use crate::libc::{mode_t, SYS_open, EACCES, O_CLOEXEC, O_RDONLY};
use crate::Result;

use core::ffi::{c_int, c_long};

pub struct Open<'a> {
    pub pathname: &'a [u8],
    pub flags: c_int,
    pub mode: Option<mode_t>,
}

impl<'a> MaybeAlloc<'a, kind::Syscall> for Open<'a> {
    type Alloc = AllocOpen<'a>;

    #[inline]
    fn stage(self) -> Result<UnstagedMaybeAlloc<'a, kind::Syscall, Self::Alloc>> {
        match self.pathname {
            b"/etc/resolv.conf\0" if self.flags & !(O_RDONLY | O_CLOEXEC) == 0 => {
                Ok(UnstagedMaybeAlloc::Alloc(AllocOpen(self)))
            }
            _ => Ok(UnstagedMaybeAlloc::Stub(Err(EACCES))),
        }
    }
}

pub struct AllocOpen<'a>(Open<'a>);

unsafe impl<'a> Alloc<'a> for AllocOpen<'a> {
    const NUM: c_long = SYS_open;

    type Argv = Argv<4>;
    type Ret = c_int;

    type Staged = Input<'a, [u8], &'a [u8]>;
    type Committed = ();
    type Collected = Result<c_int>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let pathname = Input::stage_slice(alloc, self.0.pathname)?;
        Ok((
            Argv([
                pathname.offset() as _,
                pathname.len() as _,
                self.0.flags as _,
                self.0.mode.unwrap_or(0) as _,
            ]),
            pathname,
        ))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
