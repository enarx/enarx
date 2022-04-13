// SPDX-License-Identifier: Apache-2.0

//! Calls executable by [`Handler::execute`](super::Handler::execute) and utilities to operate upon
//! them.

pub mod alloc;
pub mod enarxcall;
pub mod gdbcall;
pub mod syscall;
pub mod types;

mod maybe_alloc;
mod stub;

pub use alloc::Alloc;
pub use maybe_alloc::*;
pub use stub::*;

use crate::guest::alloc::{Allocator, Collect, Commit};
use crate::Result;

/// Call kinds.
pub mod kind {
    use super::alloc;

    use core::marker::PhantomData;

    pub trait Kind {}

    #[repr(transparent)]
    pub struct Stub;
    impl Kind for Stub {}

    #[repr(transparent)]
    pub struct Alloc<K>(PhantomData<K>)
    where
        K: alloc::kind::Kind;
    impl<K> Kind for Alloc<K> where K: alloc::kind::Kind {}

    #[repr(transparent)]
    pub struct MaybeAlloc<K>(PhantomData<K>)
    where
        K: alloc::kind::Kind;
    impl<K> Kind for MaybeAlloc<K> where K: alloc::kind::Kind {}

    impl<K> Kind for (K,) {}
    impl<AK, BK> Kind for (AK, BK) {}
    impl<AK, BK, CK> Kind for (AK, BK, CK) {}
    impl<AK, BK, CK, DK> Kind for (AK, BK, CK, DK) {}
}

/// An [executable](super::Handler::execute) call.
pub trait Call<'a, K>
where
    K: kind::Kind,
{
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

impl<'a, AK, A> Call<'a, (AK,)> for (A,)
where
    AK: kind::Kind,
    A: Call<'a, AK>,
{
    type Staged = (A::Staged,);
    type Committed = (A::Committed,);
    type Collected = (A::Collected,);

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged> {
        self.0.stage(alloc).map(|a| (a,))
    }
}

impl<'a, AK, BK, A, B> Call<'a, (AK, BK)> for (A, B)
where
    AK: kind::Kind,
    BK: kind::Kind,
    A: Call<'a, AK>,
    B: Call<'a, BK>,
{
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

impl<'a, AK, BK, CK, A, B, C> Call<'a, (AK, BK, CK)> for (A, B, C)
where
    AK: kind::Kind,
    BK: kind::Kind,
    CK: kind::Kind,
    A: Call<'a, AK>,
    B: Call<'a, BK>,
    C: Call<'a, CK>,
{
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

impl<'a, AK, BK, CK, DK, A, B, C, D> Call<'a, (AK, BK, CK, DK)> for (A, B, C, D)
where
    AK: kind::Kind,
    BK: kind::Kind,
    CK: kind::Kind,
    DK: kind::Kind,
    A: Call<'a, AK>,
    B: Call<'a, BK>,
    C: Call<'a, CK>,
    D: Call<'a, DK>,
{
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
