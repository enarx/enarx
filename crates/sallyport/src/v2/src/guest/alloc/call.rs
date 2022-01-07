// SPDX-License-Identifier: Apache-2.0

use super::{Allocator, Collect, Collector, Commit, Committer, InRef};
use crate::{guest, item, Result};

use core::alloc::Layout;
use core::mem::align_of;
use libc::ENOMEM;

pub trait Call<'a> {
    /// `[item::Kind]` this call is committed as.
    const KIND: item::Kind;

    /// Opaque [staged value](Stage::Item) value, which returns [`Self::Committed`] when committed via [`Commit::commit`].
    ///
    /// This is primarily designed to serve as a container for dynamic data allocated within [`stage`][Self::stage].
    type Staged: Commit<Item = Self::Committed>;

    /// Opaque [committed value](Commit::Item) returned by [`Commit::commit`] called upon [`Self::Staged`], which is, in turn,
    /// passed to [`Self::collect`] to yield a [`Self::Collected`].
    type Committed: Collect<Item = Self::Collected>;

    /// Value call [collects](Collect::Item) as, which corresponds to its [return value](Self::Ret).
    type Collected;

    /// Allocate dynamic data, if necessary and return resulting argument vector registers
    /// and opaque [staged value](Self::Staged) on success.
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged>;
}

impl<'a, T: Call<'a>> guest::Call<'a> for T {
    type Staged = StagedCall<'a, T>;
    type Committed = CommittedCall<'a, T>;
    type Collected = T::Collected;

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged> {
        let header_ref = alloc.allocate_input()?;
        let (staged, mut size) = alloc.section(|alloc| self.stage(alloc))?;
        if size > 0 {
            let reminder = size % align_of::<usize>();
            if reminder > 0 {
                let pad_size = align_of::<usize>() - reminder;
                size += pad_size;

                let pad_layout = Layout::from_size_align(pad_size, 1).map_err(|_| ENOMEM)?;
                alloc.allocate_input_layout(pad_layout)?;
            }
        };
        Ok(Self::Staged {
            header_ref,
            staged,
            size,
        })
    }
}

/// Staged call, which holds allocated reference to call header within the block and [opaque staged value](Call::Staged).
pub struct StagedCall<'a, T: Call<'a>> {
    header_ref: InRef<'a, item::Header>,
    staged: T::Staged,
    size: usize,
}

impl<'a, T: Call<'a>> Commit for StagedCall<'a, T> {
    type Item = CommittedCall<'a, T>;

    #[inline]
    fn commit(mut self, com: &impl Committer) -> Self::Item {
        self.header_ref.copy_from(
            com,
            item::Header {
                size: self.size,
                kind: T::KIND,
            },
        );
        Self::Item {
            committed: self.staged.commit(com),
        }
    }
}

/// Committed call, which holds allocated reference to [opaque committed value](Call::Committed).
pub struct CommittedCall<'a, T: Call<'a>> {
    committed: T::Committed,
}

impl<'a, T: Call<'a>> Collect for CommittedCall<'a, T> {
    type Item = T::Collected;

    fn collect(self, col: &impl Collector) -> Self::Item {
        self.committed.collect(col)
    }
}
