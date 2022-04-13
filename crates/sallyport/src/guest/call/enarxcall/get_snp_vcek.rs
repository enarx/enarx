// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Output};
use crate::item::enarxcall::Number;
use crate::Result;

// GetSnpVcek call, which writes the SNP VCEK in `vcek` field.
pub struct GetSnpVcek<'a> {
    pub vcek: &'a mut [u8],
}

impl<'a> Alloc<'a> for GetSnpVcek<'a> {
    const NUM: Number = Number::GetSnpVcek;

    type Argv = Argv<2>;
    type Ret = usize;

    type Staged = Output<'a, [u8], &'a mut [u8]>;
    type Committed = Self::Staged;
    type Collected = Option<Result<usize>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let vcek = Output::stage_slice(alloc, self.vcek)?;
        Ok((Argv([vcek.offset(), vcek.len()]), vcek))
    }

    fn collect(
        vcek: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret > vcek.len() => None,
            res @ Ok(ret) => {
                unsafe { vcek.collect_range(col, 0..ret) };
                Some(res)
            }
            err => Some(err),
        }
    }
}
