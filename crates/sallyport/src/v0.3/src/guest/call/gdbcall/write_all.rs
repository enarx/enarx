// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::types::StagedBytesInput;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Input};
use crate::item::gdbcall::Number;
use crate::Result;

#[cfg_attr(feature = "doc", doc = "[`gdbstub::conn::Connection::write_all`] call")]
pub struct WriteAll<'a> {
    pub buf: &'a [u8],
}

impl<'a> Alloc<'a> for WriteAll<'a> {
    const NUM: Number = Number::WriteAll;

    type Argv = Argv<2>;
    type Ret = usize;

    type Staged = StagedBytesInput<'a>;
    type Committed = usize;
    type Collected = Option<Result<usize>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let (buf, _) = Input::stage_slice_max(alloc, self.buf)?;
        Ok((Argv([buf.offset(), buf.len()]), StagedBytesInput(buf)))
    }

    fn collect(
        count: Self::Committed,
        ret: Result<Self::Ret>,
        _: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret > count => None,
            res @ Ok(_) => Some(res),
            err => Some(err),
        }
    }
}
