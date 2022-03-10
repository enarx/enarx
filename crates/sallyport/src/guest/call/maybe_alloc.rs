// SPDX-License-Identifier: Apache-2.0

use super::alloc::kind;
use super::{Alloc, Call};
use crate::guest::alloc::{Allocator, Collect, Collector, Commit, Committer};
use crate::Result;

pub enum UnstagedMaybeAlloc<'a, K, T>
where
    K: kind::Kind,
    T: Alloc<'a, K>,
{
    Alloc(T),
    Stub(T::Collected),
}

/// A call, which *may* result in allocation within the block.
pub trait MaybeAlloc<'a, K>
where
    K: kind::Kind,
{
    type Alloc: Alloc<'a, K>;

    fn stage(self) -> Result<UnstagedMaybeAlloc<'a, K, Self::Alloc>>;
}

impl<'a, K, T> Call<'a, super::kind::MaybeAlloc<K>> for T
where
    K: kind::Kind,
    T: MaybeAlloc<'a, K>,
{
    type Staged = StagedMaybeAlloc<'a, K, T::Alloc>;
    type Committed = CommittedMaybeAlloc<'a, K, T::Alloc>;
    type Collected = <T::Alloc as Alloc<'a, K>>::Collected;

    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged> {
        match T::stage(self)? {
            UnstagedMaybeAlloc::Alloc(unstaged) => {
                Call::stage(unstaged, alloc).map(StagedMaybeAlloc::Alloc)
            }
            UnstagedMaybeAlloc::Stub(val) => Ok(StagedMaybeAlloc::Stub(val)),
        }
    }
}

pub enum StagedMaybeAlloc<'a, K, T>
where
    K: kind::Kind,
    T: Call<'a, super::kind::Alloc<K>>,
{
    Alloc(T::Staged),
    Stub(T::Collected),
}

impl<'a, K, T> Commit for StagedMaybeAlloc<'a, K, T>
where
    K: kind::Kind,
    T: Call<'a, super::kind::Alloc<K>>,
{
    type Item = CommittedMaybeAlloc<'a, K, T>;

    fn commit(self, com: &impl Committer) -> Self::Item {
        match self {
            StagedMaybeAlloc::Alloc(staged) => CommittedMaybeAlloc::Alloc(staged.commit(com)),
            StagedMaybeAlloc::Stub(val) => CommittedMaybeAlloc::Stub(val),
        }
    }
}

pub enum CommittedMaybeAlloc<'a, K, T>
where
    K: kind::Kind,
    T: Call<'a, super::kind::Alloc<K>>,
{
    Alloc(T::Committed),
    Stub(T::Collected),
}

impl<'a, K, T> Collect for CommittedMaybeAlloc<'a, K, T>
where
    K: kind::Kind,
    T: Call<'a, super::kind::Alloc<K>>,
{
    type Item = T::Collected;

    fn collect(self, col: &impl Collector) -> Self::Item {
        match self {
            CommittedMaybeAlloc::Alloc(committed) => committed.collect(col),
            CommittedMaybeAlloc::Stub(val) => val,
        }
    }
}
