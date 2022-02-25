// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Commit, Committer, Input, Output};
use crate::item::enarxcall::sgx::Report;
use crate::item::enarxcall::Number;
use crate::Result;

use core::mem::size_of;

// GetSgxQuote call, which writes the SGX quote in `quote` field.
pub struct GetSgxQuote<'a> {
    pub report: &'a Report,
    pub quote: &'a mut [u8],
}

pub struct StagedGetSgxQuote<'a> {
    report: Input<'a, [u8; size_of::<Report>()], &'a [u8; size_of::<Report>()]>,
    quote: Output<'a, [u8], &'a mut [u8]>,
}

impl<'a> Commit for StagedGetSgxQuote<'a> {
    type Item = Output<'a, [u8], &'a mut [u8]>;

    fn commit(self, com: &impl Committer) -> Self::Item {
        self.report.commit(com);
        self.quote.commit(com)
    }
}

impl<'a> Alloc<'a> for GetSgxQuote<'a> {
    const NUM: Number = Number::GetSgxQuote;

    type Argv = Argv<3>;
    type Ret = usize;

    type Staged = StagedGetSgxQuote<'a>;
    type Committed = Output<'a, [u8], &'a mut [u8]>;
    type Collected = Option<Result<usize>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let report = Input::stage(alloc, self.report.as_ref())?;
        let quote = Output::stage_slice(alloc, self.quote)?;
        Ok((
            Argv([report.offset(), quote.offset(), quote.len()]),
            StagedGetSgxQuote { report, quote },
        ))
    }

    fn collect(
        quote: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret > quote.len() => None,
            res @ Ok(ret) => {
                unsafe { quote.collect_range(col, 0..ret) };
                Some(res)
            }
            err => Some(err),
        }
    }
}
