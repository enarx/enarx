// SPDX-License-Identifier: Apache-2.0

use super::alloc::{Allocator, Collect, Commit};
use crate::Result;

/// An [executable](super::Execute::execute) call.
pub trait Call<'a> {
    /// Opaque staged value, which returns [`Self::Committed`] when committed via [`Commit::commit`].
    ///
    /// This is designed to serve as a container for data allocated within [`stage`][Self::stage].
    type Staged: Commit<Item = Self::Committed>;

    /// Opaque [committed value](Commit::Item) returned by [`Commit::commit`] called upon [`Self::Staged`],
    /// which is, in turn, passed to [`Collect::collect`] to yield a [`Self::Collected`].
    type Committed: Collect<Item = Self::Collected>;

    /// Value call [collects](Collect::Item) as.
    ///
    /// For example, a syscall return value.
    type Collected;

    /// Allocate data, if necessary and return resulting opaque [staged value](Self::Staged) on success.
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged>;
}

impl<'a, A: Call<'a>> Call<'a> for (A,) {
    type Staged = (A::Staged,);
    type Committed = (A::Committed,);
    type Collected = (A::Collected,);

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged> {
        self.0.stage(alloc).map(|a| (a,))
    }
}

impl<'a, A: Call<'a>, B: Call<'a>> Call<'a> for (A, B) {
    type Staged = (A::Staged, B::Staged);
    type Committed = (A::Committed, B::Committed);
    type Collected = (A::Collected, B::Collected);

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged> {
        let a = self.0.stage(alloc)?;
        let b = self.1.stage(alloc)?;
        Ok((a, b))
    }
}

impl<'a, A: Call<'a>, B: Call<'a>, C: Call<'a>> Call<'a> for (A, B, C) {
    type Staged = (A::Staged, B::Staged, C::Staged);
    type Committed = (A::Committed, B::Committed, C::Committed);
    type Collected = (A::Collected, B::Collected, C::Collected);

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged> {
        ((self.0, self.1), self.2)
            .stage(alloc)
            .map(|((a, b), c)| (a, b, c))
    }
}

impl<'a, A: Call<'a>, B: Call<'a>, C: Call<'a>, D: Call<'a>> Call<'a> for (A, B, C, D) {
    type Staged = (A::Staged, B::Staged, C::Staged, D::Staged);
    type Committed = (A::Committed, B::Committed, C::Committed, D::Committed);
    type Collected = (A::Collected, B::Collected, C::Collected, D::Collected);

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged> {
        ((self.0, self.1), self.2, self.3)
            .stage(alloc)
            .map(|((a, b), c, d)| (a, b, c, d))
    }
}
