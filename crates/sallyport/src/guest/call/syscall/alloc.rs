// SPDX-License-Identifier: Apache-2.0

use super::super::alloc;
use super::types::{self, CommittedAlloc, StagedAlloc};
use crate::guest::alloc::{Allocator, Collector, Commit};
use crate::Result;

use core::ffi::c_long;

/// A generic syscall, which can be allocated within the block.
///
/// # Safety
///
/// This trait is unsafe, because it allows execution arbitrary syscalls on the host, which is
/// intrinsically unsafe.
///
/// # Examples
///
/// ```rust
/// # #![feature(c_size_t)]
/// use sallyport::guest::alloc::{Allocator, Collector, Output};
/// use sallyport::guest::call::types::Argv;
/// use sallyport::guest::syscall::Alloc;
/// use sallyport::Result;
/// #
/// # use sallyport::libc;
/// # use core::ffi::{c_int, c_long, c_size_t};
///
/// pub struct Read<'a> {
///    pub fd: c_int,
///    pub buf: &'a mut [u8],
/// }
///
/// unsafe impl<'a> Alloc<'a> for Read<'a> {
///     const NUM: c_long = libc::SYS_read;
///
///     type Argv = Argv<3>;
///     type Ret = c_size_t;
///
///     type Staged = Output<'a, [u8], &'a mut [u8]>;
///     type Committed = Self::Staged;
///     type Collected = Option<Result<c_size_t>>;
///
///     fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
///         let (buf, _) = Output::stage_slice_max(alloc, self.buf)?;
///         Ok((Argv([self.fd as _, buf.offset(), buf.len()]), buf))
///     }
///
///     fn collect(
///         buf: Self::Committed,
///         ret: Result<Self::Ret>,
///         col: &impl Collector,
///     ) -> Self::Collected {
///         match ret {
///             Ok(ret) if ret > buf.len() => None,
///             res @ Ok(ret) => {
///                 unsafe { buf.collect_range(col, 0..ret) };
///                 Some(res)
///             }
///             err => Some(err),
///         }
///     }
/// }
/// ```
pub unsafe trait Alloc<'a> {
    /// Syscall number.
    ///
    /// For example, [`libc::SYS_read`].
    const NUM: c_long;

    /// The syscall argument vector.
    ///
    /// For example, [`guest::call::types::Argv<3>`](super::super::types::Argv<3>).
    type Argv: Into<[usize; 6]>;

    /// Syscall return value.
    ///
    /// For example, [`libc::size_t`].
    type Ret;

    /// Opaque staged value, which returns [`Self::Committed`] when committed via [`Commit::commit`].
    ///
    /// This is designed to serve as a container for dynamic data allocated within [`stage`][Self::stage].
    ///
    /// For example, [`Output<'a, [u8], &'a mut [u8]>`](crate::guest::alloc::Output).
    type Staged: Commit<Item = Self::Committed>;

    /// Opaque [committed value](crate::guest::alloc::Commit::Item)
    /// returned by [`guest::alloc::Commit::commit`](crate::guest::alloc::Commit::commit)
    /// called upon [`Self::Staged`], which returns [`Self::Collected`] when
    /// collected via [`guest::alloc::Collect::collect`](crate::guest::alloc::Collect::collect).
    type Committed;

    /// Value syscall [collects](crate::guest::alloc::Collect::Item) as, which corresponds to its [return value](Self::Ret).
    ///
    /// For example, [`Option<Result<libc::size_t>>`].
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

impl<'a, T: Alloc<'a>> super::super::Alloc<'a, alloc::kind::Syscall> for T
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
