// SPDX-License-Identifier: Apache-2.0

//! Generic allocatable call-specific functionality.

use super::Call;
use crate::guest::alloc::{Allocator, Collect, Collector, Commit, Committer, InRef};
use crate::libc::ENOMEM;
use crate::{item, Result};

use core::alloc::Layout;
use core::mem::align_of;

/// Allocatable call kinds.
pub(crate) mod kind {
    use crate::item;

    pub trait Kind {
        /// [`item::Kind`] of this call.
        const ITEM: item::Kind;
    }

    #[repr(transparent)]
    pub struct Syscall;
    impl Kind for Syscall {
        const ITEM: item::Kind = item::Kind::Syscall;
    }

    #[repr(transparent)]
    pub struct Gdbcall;
    impl Kind for Gdbcall {
        const ITEM: item::Kind = item::Kind::Gdbcall;
    }

    #[repr(transparent)]
    pub struct Enarxcall;
    impl Kind for Enarxcall {
        const ITEM: item::Kind = item::Kind::Enarxcall;
    }
}

/// A generic call, which can be allocated within the block.
pub trait Alloc<'a, K>
where
    K: kind::Kind,
{
    /// Opaque staged value, which returns [`Self::Committed`] when committed via [`Commit::commit`].
    ///
    /// This is designed to serve as a container for data allocated within [`stage`][Self::stage].
    type Staged: Commit<Item = Self::Committed>;

    /// Opaque [committed value](Commit::Item) returned by [`Commit::commit`] called upon [`Self::Staged`],
    /// which returns [`Self::Collected`] when collected via [`Collect::collect`].
    type Committed: Collect<Item = Self::Collected>;

    /// Value call [collects](Collect::Item) as.
    /// For example, a syscall return value.
    type Collected;

    /// Allocate data, if necessary, and return resulting opaque [staged value](Self::Staged) on success.
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Staged>;
}

impl<'a, K, T> Call<'a, super::kind::Alloc<K>> for T
where
    K: kind::Kind,
    T: Alloc<'a, K>,
{
    type Staged = StagedCall<'a, K, T>;
    type Committed = CommittedCall<'a, K, T>;
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

/// Staged call, which holds allocated reference to item header within the block and [opaque staged value](Call::Staged).
pub struct StagedCall<'a, K, T>
where
    K: kind::Kind,
    T: Alloc<'a, K>,
{
    header_ref: InRef<'a, item::Header>,
    staged: T::Staged,
    size: usize,
}

impl<'a, K, T> Commit for StagedCall<'a, K, T>
where
    K: kind::Kind,
    T: Alloc<'a, K>,
{
    type Item = CommittedCall<'a, K, T>;

    #[inline]
    fn commit(mut self, com: &impl Committer) -> Self::Item {
        self.header_ref.copy_from(
            com,
            item::Header {
                size: self.size,
                kind: K::ITEM,
            },
        );
        Self::Item {
            committed: self.staged.commit(com),
        }
    }
}

/// Committed call, which holds allocated reference to [opaque committed value](Call::Committed).
pub struct CommittedCall<'a, K, T>
where
    K: kind::Kind,
    T: Alloc<'a, K>,
{
    committed: T::Committed,
}

impl<'a, K, T> Collect for CommittedCall<'a, K, T>
where
    K: kind::Kind,
    T: Alloc<'a, K>,
{
    type Item = T::Collected;

    fn collect(self, col: &impl Collector) -> Self::Item {
        self.committed.collect(col)
    }
}
