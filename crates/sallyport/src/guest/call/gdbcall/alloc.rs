// SPDX-License-Identifier: Apache-2.0

use super::super::alloc;
use super::types::{self, CommittedAlloc, StagedAlloc};
use crate::guest::alloc::{Allocator, Collector, Commit};
use crate::item::gdbcall::Number;
use crate::Result;

/// A generic GDB call, which can be allocated within the block.
///
/// # Examples
///
/// ```rust
/// use sallyport::item::gdbcall::Number;
/// use sallyport::guest::alloc::{Allocator, Collector, Input};
/// use sallyport::guest::call::types::Argv;
/// use sallyport::guest::gdbcall::Alloc;
/// use sallyport::guest::gdbcall::types::{StagedBytesInput};
/// use sallyport::Result;
///
/// pub struct WriteAll<'a> {
///     pub buf: &'a [u8],
/// }
///
/// impl<'a> Alloc<'a> for WriteAll<'a> {
///     const NUM: Number = Number::WriteAll;
///
///     type Argv = Argv<2>;
///     type Ret = usize;
///
///     type Staged = StagedBytesInput<'a>;
///     type Committed = usize;
///     type Collected = Option<Result<usize>>;
///
///     fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
///         let (buf, _) = Input::stage_slice_max(alloc, self.buf)?;
///         Ok((Argv([buf.offset(), buf.len()]), StagedBytesInput(buf)))
///     }
///
///     fn collect(
///         count: Self::Committed,
///         ret: Result<Self::Ret>,
///         _: &impl Collector,
///     ) -> Self::Collected {
///         match ret {
///             Ok(ret) if ret > count => None,
///             res @ Ok(_) => Some(res),
///             err => Some(err),
///         }
///     }
/// }
/// ```
pub trait Alloc<'a> {
    /// GDB call number.
    ///
    /// For example, [`item::gdbcall::Number::WriteAll`](Number::WriteAll).
    const NUM: Number;

    /// The GDB call argument vector.
    ///
    /// For example, [`guest::call::types::Argv<2>`](super::super::types::Argv<2>).
    type Argv: Into<[usize; 4]>;

    /// GDB call return value.
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

    /// Value GDB call [collects](crate::guest::alloc::Collect::Item) as, which corresponds to its [return value](Self::Ret).
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

impl<'a, T: Alloc<'a>> super::super::Alloc<'a, alloc::kind::Gdbcall> for T
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
