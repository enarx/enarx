// SPDX-License-Identifier: Apache-2.0

use super::Alloc;
use crate::guest::alloc::{Allocator, Collector};
use crate::item::enarxcall::Number;
use crate::Result;

/// Trait implemented by allocatable Enarx calls, which are passed through directly to the host and do
/// not require custom handling logic.
pub trait PassthroughAlloc {
    /// Enarx call number.
    ///
    /// For example, [`Number::BalloonMemory`].
    const NUM: Number;

    /// The Enarx call argument vector.
    ///
    /// For example, [`call::types::Argv<3>`](crate::guest::call::types::Argv<3>).
    type Argv: Into<[usize; 4]>;

    /// Enarx call return value.
    ///
    /// For example, `usize`.
    type Ret;

    /// Returns argument vector registers.
    fn stage(self) -> Self::Argv;
}

impl<'a, T: PassthroughAlloc> Alloc<'a> for T {
    const NUM: Number = T::NUM;

    type Argv = T::Argv;
    type Ret = T::Ret;

    type Staged = ();
    type Committed = ();
    type Collected = Result<T::Ret>;

    fn stage(self, _: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        Ok((T::stage(self), ()))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
