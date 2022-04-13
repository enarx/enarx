// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collect, Collector, Output};
use crate::item::enarxcall::Number;
use crate::Result;

use core::arch::x86_64::CpuidResult;

/// Cpuid Enarx call, which writes the [result](CpuidResult) of the `cpuid` instruction
/// for a given `leaf` (`EAX`) and `sub_leaf` (`ECX`) in `result` field.
pub struct Cpuid<'a> {
    pub leaf: u32,
    pub sub_leaf: u32,
    pub result: &'a mut CpuidResult,
}

impl<'a> Alloc<'a> for Cpuid<'a> {
    const NUM: Number = Number::Cpuid;

    type Argv = Argv<3>;
    type Ret = ();

    type Staged = Output<'a, CpuidResult, &'a mut CpuidResult>;
    type Committed = Self::Staged;
    type Collected = Result<()>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let result = Output::stage(alloc, self.result)?;
        Ok((
            Argv([self.leaf as _, self.sub_leaf as _, result.offset()]),
            result,
        ))
    }

    fn collect(
        result: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        if ret.is_ok() {
            result.collect(col);
        }
        ret
    }
}
