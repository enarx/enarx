// SPDX-License-Identifier: Apache-2.0

use super::super::alloc;
use super::types::{self, CommittedAlloc, StagedAlloc};
use crate::guest::alloc::{Allocator, Collector, Commit};
use crate::item::enarxcall::Number;
use crate::Result;

/// A generic Enarx call, which can be allocated within the block.
pub trait Alloc<'a> {
    /// Enarx call number.
    ///
    /// For example, [`item::enarxcall::Number::Cpuid`](Number::Cpuid).
    const NUM: Number;

    /// The Enarx call argument vector.
    ///
    /// For example, [`guest::call::types::Argv<2>`](super::super::types::Argv<2>).
    type Argv: Into<[usize; 4]>;

    /// Enarx call return value.
    ///
    /// For example, [`usize`].
    type Ret;

    /// Opaque staged value, which returns [`Self::Committed`] when committed via [`Commit::commit`].
    ///
    /// This is designed to serve as a container for dynamic data allocated within [`stage`][Self::stage].
    ///
    /// For example, [`Input<'a, [u8], &'a [u8]>`](crate::guest::alloc::Input).
    type Staged: Commit<Item = Self::Committed>;

    /// Opaque [committed value](crate::guest::alloc::Commit::Item)
    /// returned by [`guest::alloc::Commit::commit`](crate::guest::alloc::Commit::commit)
    /// called upon [`Self::Staged`], which returns [`Self::Collected`] when
    /// collected via [`guest::alloc::Collect::collect`](crate::guest::alloc::Collect::collect).
    type Committed;

    /// Value Enarx call [collects](crate::guest::alloc::Collect::Item) as, which corresponds to its [return value](Self::Ret).
    ///
    /// For example, [`Option<Result<usize>>`].
    type Collected;

    /// Allocate dynamic data, if necessary and return resulting argument vector registers
    /// and opaque [staged value](Self::Staged) on success.
    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)>;

    /// Collect the return registers, [opaque committed value](Self::Committed)
    /// and return a [`Self::Collected`].
    fn collect(
        committed: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected;
}

impl<'a, T: Alloc<'a>> super::super::Alloc<'a, alloc::kind::Enarxcall> for T
where
    types::Result<T::Ret>: Into<Result<T::Ret>>,
{
    type Staged = StagedAlloc<'a, T>;
    type Committed = CommittedAlloc<'a, T>;
    type Collected = T::Collected;

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged> {
        let num_ref = alloc.allocate_input()?;
        let argv_ref = alloc.allocate_input()?;
        let ret_ref = alloc.allocate_inout()?;
        let ((argv, staged), _) = alloc.section(|alloc| self.stage(alloc))?;
        Ok(Self::Staged {
            num_ref,
            argv: argv_ref.stage(argv.into()),
            ret_ref,
            staged,
        })
    }
}
