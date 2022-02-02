// SPDX-License-Identifier: Apache-2.0

use super::{
    kind, Allocator, Call, Collect, Collector, Commit, Committer, InOutRef, InRef, Input, OutRef,
};
use crate::guest::syscall;
use crate::Result;

use libc::c_long;

/// A generic syscall, which can be allocated within the block.
///
/// # Examples
///
/// ```rust
/// use sallyport::guest::syscall::types::Argv;
/// # use sallyport::guest::alloc::{Allocator, Collector, Output, Syscall};
/// # use sallyport::Result;
/// #
/// # use libc::{c_int, c_long, size_t};
///
/// pub struct Read<'a> {
///    pub fd: c_int,
///    pub buf: &'a mut [u8],
/// }
///
/// unsafe impl<'a> Syscall<'a> for Read<'a> {
///     const NUM: c_long = libc::SYS_read;
///
///     type Argv = Argv<3>;
///     type Ret = size_t;
///
///     type Staged = Output<'a, [u8], &'a mut [u8]>;
///     type Committed = Self::Staged;
///     type Collected = Option<Result<size_t>>;
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
pub unsafe trait Syscall<'a> {
    /// Syscall number.
    ///
    /// For example, [`libc::SYS_read`].
    const NUM: c_long;

    /// The syscall argument vector.
    ///
    /// For example, [`syscall::types::Argv<3>`].
    type Argv: Into<[usize; 6]>;

    /// Syscall return value.
    ///
    /// For example, [`libc::size_t`].
    type Ret;

    /// Opaque staged value, which returns [`Self::Committed`] when committed via [`Commit::commit`].
    ///
    /// This is designed to serve as a container for dynamic data allocated within [`stage`][Self::stage].
    ///
    /// For example, [`Output<'a, [u8], &'a mut [u8]>`](super::Output).
    type Staged: Commit<Item = Self::Committed>;

    /// Opaque [committed value](Commit::Item) returned by [`Commit::commit`] called upon [`Self::Staged`],
    /// which returns [`Self::Collected`] when collected via [`Collect::collect`].
    type Committed;

    /// Value syscall [collects](Collect::Item) as, which corresponds to its [return value](Self::Ret).
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

impl<'a, T: Syscall<'a>> Call<'a, kind::Syscall> for T
where
    syscall::Result<T::Ret>: Into<Result<T::Ret>>,
{
    type Staged = StagedSyscall<'a, T>;
    type Committed = CommittedSyscall<'a, T>;
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

/// Staged syscall, which holds allocated reference to syscall item within the block and [opaque staged value](Syscall::Staged).
pub struct StagedSyscall<'a, T: Syscall<'a>> {
    num_ref: InRef<'a, usize>,
    argv: Input<'a, [usize; 6], [usize; 6]>,
    ret_ref: InOutRef<'a, [usize; 2]>,
    staged: T::Staged,
}

impl<'a, T: Syscall<'a>> Commit for StagedSyscall<'a, T> {
    type Item = CommittedSyscall<'a, T>;

    #[inline]
    fn commit(mut self, com: &impl Committer) -> Self::Item {
        self.num_ref.copy_from(com, T::NUM as usize);
        self.argv.commit(com);
        self.ret_ref.copy_from(com, [-libc::ENOSYS as usize, 0]);
        Self::Item {
            ret_ref: self.ret_ref.commit(com),
            committed: self.staged.commit(com),
        }
    }
}

/// Committed syscall, which holds allocated reference to syscall return values within the block and [opaque committed value](Syscall::Committed).
pub struct CommittedSyscall<'a, T: Syscall<'a>> {
    ret_ref: OutRef<'a, [usize; 2]>,
    committed: T::Committed,
}

impl<'a, T: Syscall<'a>> Collect for CommittedSyscall<'a, T>
where
    syscall::Result<T::Ret>: Into<Result<T::Ret>>,
{
    type Item = T::Collected;

    #[inline]
    fn collect(self, col: &impl Collector) -> Self::Item {
        let mut ret = [0usize; 2];
        self.ret_ref.copy_to(col, &mut ret);
        let res: syscall::Result<T::Ret> = ret.into();
        T::collect(self.committed, res.into(), col)
    }
}

/// Trait implemented by allocatable syscalls, which are passed through directly to the host and do
/// not require custom handling logic.
///
/// # Example
/// ```rust
/// use sallyport::guest::syscall::types::Argv;
/// # use sallyport::guest::alloc::{PassthroughSyscall};
/// # use sallyport::Result;
/// #
/// # use libc::{c_int, c_long};
///
/// pub struct Exit {
///     pub status: c_int,
/// }
///
/// unsafe impl PassthroughSyscall for Exit {
///     const NUM: c_long = libc::SYS_exit;
///
///     type Argv = Argv<1>;
///     type Ret = ();
///
///     fn stage(self) -> Self::Argv {
///         Argv([self.status as _])
///     }
/// }
/// ```
pub unsafe trait PassthroughSyscall {
    /// Syscall number.
    ///
    /// For example, [`libc::SYS_exit`].
    const NUM: c_long;

    /// The syscall argument vector.
    ///
    /// For example, [`syscall::types::Argv<1>`].
    type Argv: Into<[usize; 6]>;

    /// Syscall return value.
    ///
    /// For example, `()`.
    type Ret;

    /// Returns argument vector registers.
    fn stage(self) -> Self::Argv;
}

unsafe impl<'a, T: PassthroughSyscall> Syscall<'a> for T {
    const NUM: c_long = T::NUM;

    type Argv = T::Argv;
    type Ret = T::Ret;

    type Staged = ();
    type Committed = ();
    type Collected = Result<T::Ret>;

    fn stage(self, _: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        Ok((T::stage(self), ()))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
