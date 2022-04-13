// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector};
use crate::item::gdbcall::Number;
use crate::Result;

/// Trait implemented by allocatable GDB calls, which are passed through directly to the host and do
/// not require custom handling logic.
///
/// # Example
/// ```rust
/// use sallyport::item::gdbcall::Number;
/// use sallyport::guest::call::types::Argv;
/// use sallyport::guest::gdbcall::PassthroughAlloc;
/// use sallyport::Result;
///
/// pub struct Read;
///
/// impl PassthroughAlloc for Read {
///     const NUM: Number = Number::Read;
///
///     type Argv = Argv<0>;
///     type Ret = u8;
///
///     fn stage(self) -> Self::Argv {
///         Argv([])
///     }
/// }
/// ```
pub trait PassthroughAlloc {
    /// GDB call number.
    ///
    /// For example, [`Number::Read`].
    const NUM: Number;

    /// The gdbcall argument vector.
    ///
    /// For example, [`call::types::Argv<0>`](crate::guest::call::types::Argv<0>).
    type Argv: Into<[usize; 4]>;

    /// Gdbcall return value.
    ///
    /// For example, `u8`.
    type Ret;

    /// Returns argument vector registers.
    fn stage(self) -> Self::Argv;
}

impl<'a, T: PassthroughAlloc> Alloc<'a> for T {
    const NUM: Number = T::NUM;

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

#[cfg_attr(feature = "doc", doc = "[`gdbstub::conn::Connection::flush`] call")]
#[repr(transparent)]
pub struct Flush;

impl PassthroughAlloc for Flush {
    const NUM: Number = Number::Flush;

    type Argv = Argv<0>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}

#[cfg_attr(
    feature = "doc",
    doc = "[`gdbstub::conn::Connection::on_session_start`] call"
)]
#[repr(transparent)]
pub struct OnSessionStart;

impl PassthroughAlloc for OnSessionStart {
    const NUM: Number = Number::OnSessionStart;

    type Argv = Argv<0>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}

#[cfg_attr(feature = "doc", doc = "[`gdbstub::conn::ConnectionExt::peek`] call")]
#[repr(transparent)]
pub struct Peek;

impl PassthroughAlloc for Peek {
    const NUM: Number = Number::Peek;

    type Argv = Argv<0>;
    type Ret = Option<u8>;

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}

#[cfg_attr(feature = "doc", doc = "[`gdbstub::conn::ConnectionExt::read`] call")]
#[repr(transparent)]
pub struct Read;

impl PassthroughAlloc for Read {
    const NUM: Number = Number::Read;

    type Argv = Argv<0>;
    type Ret = u8;

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}

#[cfg_attr(feature = "doc", doc = "[`gdbstub::conn::Connection::write`] call")]
#[repr(transparent)]
pub struct Write {
    pub byte: u8,
}

impl PassthroughAlloc for Write {
    const NUM: Number = Number::Write;

    type Argv = Argv<1>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.byte as _])
    }
}
