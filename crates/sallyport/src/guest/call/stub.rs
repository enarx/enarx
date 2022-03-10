// SPDX-License-Identifier: Apache-2.0

use crate::guest::alloc::{Allocator, Collect, Collector, CommitPassthrough};
use crate::Result;

use super::{kind, Call};

/// A call, which does not result in an allocation within the block.
pub trait Stub {
    /// Call return value.
    ///
    /// For example, [`libc::size_t`].
    type Ret;

    fn collect(self, _: &impl Collector) -> Self::Ret;
}

impl<T: Stub> Call<'_, kind::Stub> for T {
    type Staged = Self;
    type Committed = Self;
    type Collected = T::Ret;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Staged> {
        Ok(self)
    }
}
impl<T: Stub> CommitPassthrough for T {}
impl<T: Stub> Collect for T {
    type Item = T::Ret;

    fn collect(self, col: &impl Collector) -> Self::Item {
        self.collect(col)
    }
}
