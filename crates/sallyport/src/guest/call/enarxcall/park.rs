// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Input};
use crate::item::enarxcall::Number;
use crate::libc::timespec;
use crate::{Result, NULL};

use core::ffi::c_int;

#[derive(Debug, Clone, Copy)]
pub struct Park<'a> {
    pub expected_val: c_int,
    pub timeout: Option<&'a timespec>,
}

impl<'a> Alloc<'a> for Park<'a> {
    const NUM: Number = Number::Park;

    type Argv = Argv<2>;
    type Ret = c_int;

    type Staged = Option<Input<'a, timespec, &'a timespec>>;
    type Committed = Option<()>;
    type Collected = Result<c_int>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let (timeout, timeout_offset) = if let Some(timeout) = self.timeout {
            let timeout = Input::stage(alloc, timeout)?;
            let timeout_offset = timeout.offset();
            (Some(timeout), timeout_offset)
        } else {
            (None, NULL)
        };
        Ok((Argv([self.expected_val as _, timeout_offset]), timeout))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
