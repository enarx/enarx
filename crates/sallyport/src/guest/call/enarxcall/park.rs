// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Input};
use crate::item::enarxcall::Number;
use crate::libc::timespec;
use crate::{Result, NULL};

#[derive(Debug, Clone, Copy)]
pub struct ParkTimeout {
    pub timespec: timespec,
    pub absolute: bool,
}

pub struct Park<'a> {
    pub timeout: Option<&'a ParkTimeout>,
}

impl<'a> Alloc<'a> for Park<'a> {
    const NUM: Number = Number::Park;

    type Argv = Argv<1>;
    type Ret = ();

    type Staged = Option<Input<'a, ParkTimeout, &'a ParkTimeout>>;
    type Committed = Option<()>;
    type Collected = Result<()>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let (timeout, timeout_offset) = if let Some(timeout) = self.timeout {
            let timeout = Input::stage(alloc, timeout)?;
            let timeout_offset = timeout.offset();
            (Some(timeout), timeout_offset)
        } else {
            (None, NULL)
        };
        Ok((Argv([timeout_offset]), timeout))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
