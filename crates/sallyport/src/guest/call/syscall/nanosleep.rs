// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collect, Collector, Commit, Committer, InOut, Input, Output};
use crate::libc::{timespec, SYS_nanosleep, EINTR};
use crate::{Result, NULL};

use core::ffi::c_long;

pub struct Nanosleep<'a> {
    pub req: &'a timespec,
    pub rem: Option<&'a mut timespec>,
}

pub struct StagedNanosleep<'a> {
    req: Input<'a, timespec, &'a timespec>,
    rem: Option<InOut<'a, timespec, &'a mut timespec>>,
}

impl<'a> Commit for StagedNanosleep<'a> {
    type Item = Option<Output<'a, timespec, &'a mut timespec>>;

    fn commit(self, com: &impl Committer) -> Self::Item {
        self.req.commit(com);
        self.rem.commit(com)
    }
}

unsafe impl<'a> Alloc<'a> for Nanosleep<'a> {
    const NUM: c_long = SYS_nanosleep;

    type Argv = Argv<2>;
    type Ret = ();

    type Staged = StagedNanosleep<'a>;
    type Committed = Option<Output<'a, timespec, &'a mut timespec>>;
    type Collected = Result<()>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let req = Input::stage(alloc, self.req)?;
        let (rem, rem_offset) = if let Some(rem) = self.rem {
            let rem = InOut::stage(alloc, rem)?;
            let rem_offset = rem.offset();
            (Some(rem), rem_offset)
        } else {
            (None, NULL)
        };
        Ok((Argv([req.offset(), rem_offset]), Self::Staged { req, rem }))
    }

    fn collect(
        rem: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        if let Err(EINTR) = ret {
            rem.collect(col);
        };
        ret
    }
}
