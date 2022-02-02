// SPDX-License-Identifier: Apache-2.0

use super::{kind, Allocator, Call, Collect, Collector, Commit, Committer};
use crate::Result;

pub trait MaybeAlloc<'a, K, T>
where
    K: kind::Kind,
    T: Call<'a, K>,
{
    fn stage(self, alloc: &mut impl Allocator) -> Result<StagedMaybeAlloc<'a, K, T>>;
}

impl<'a, K, T, M> Call<'a, kind::MaybeAlloc<'a, K, T>> for M
where
    K: kind::Kind,
    T: Call<'a, K>,
    M: MaybeAlloc<'a, K, T>,
{
    type Staged = StagedMaybeAlloc<'a, K, T>;
    type Committed = CommittedMaybeAlloc<'a, K, T>;
    type Collected = T::Collected;

    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged> {
        M::stage(self, alloc)
    }
}

pub enum StagedMaybeAlloc<'a, K, T>
where
    K: kind::Kind,
    T: Call<'a, K>,
{
    Alloc(T::Staged),
    Stub(T::Collected),
}

impl<'a, K, T> Commit for StagedMaybeAlloc<'a, K, T>
where
    K: kind::Kind,
    T: Call<'a, K>,
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
    T: Call<'a, K>,
{
    Alloc(T::Committed),
    Stub(T::Collected),
}

impl<'a, K, T> Collect for CommittedMaybeAlloc<'a, K, T>
where
    K: kind::Kind,
    T: Call<'a, K>,
{
    type Item = T::Collected;

    fn collect(self, col: &impl Collector) -> Self::Item {
        match self {
            CommittedMaybeAlloc::Alloc(committed) => committed.collect(col),
            CommittedMaybeAlloc::Stub(val) => val,
        }
    }
}
