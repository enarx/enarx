// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector};
use crate::libc::{
    SYS_close, SYS_dup, SYS_dup2, SYS_dup3, SYS_epoll_create1, SYS_eventfd2, SYS_exit,
    SYS_exit_group, SYS_listen, SYS_socket, SYS_sync,
};
use crate::Result;

use core::ffi::{c_int, c_long};

/// Trait implemented by allocatable syscalls, which are passed through directly to the host and do
/// not require custom handling logic.
///
/// # Safety
///
/// This trait is unsafe, because it allows execution arbitrary syscalls on the host, which is
/// intrinsically unsafe.
///
/// # Example
/// ```rust
/// use sallyport::guest::call::types::Argv;
/// use sallyport::guest::syscall::PassthroughAlloc;
/// use sallyport::Result;
/// #
/// # use sallyport::libc;
/// # use core::ffi::{c_int, c_long};
///
/// pub struct Exit {
///     pub status: c_int,
/// }
///
/// unsafe impl PassthroughAlloc for Exit {
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
pub unsafe trait PassthroughAlloc {
    /// Syscall number.
    ///
    /// For example, [`libc::SYS_exit`].
    const NUM: c_long;

    /// The syscall argument vector.
    ///
    /// For example, [`call::types::Argv<1>`](crate::guest::call::types::Argv<1>).
    type Argv: Into<[usize; 6]>;

    /// Syscall return value.
    ///
    /// For example, `()`.
    type Ret;

    /// Returns argument vector registers.
    fn stage(self) -> Self::Argv;
}

unsafe impl<'a, T: PassthroughAlloc> Alloc<'a> for T {
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

pub struct Close {
    pub fd: c_int,
}

unsafe impl PassthroughAlloc for Close {
    const NUM: c_long = SYS_close;

    type Argv = Argv<1>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.fd as _])
    }
}

pub struct Dup {
    pub oldfd: c_int,
}

unsafe impl PassthroughAlloc for Dup {
    const NUM: c_long = SYS_dup;

    type Argv = Argv<1>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.oldfd as _])
    }
}

pub struct Dup2 {
    pub oldfd: c_int,
    pub newfd: c_int,
}

unsafe impl PassthroughAlloc for Dup2 {
    const NUM: c_long = SYS_dup2;

    type Argv = Argv<2>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.oldfd as _, self.newfd as _])
    }
}

pub struct Dup3 {
    pub oldfd: c_int,
    pub newfd: c_int,
    pub flags: c_int,
}

unsafe impl PassthroughAlloc for Dup3 {
    const NUM: c_long = SYS_dup3;

    type Argv = Argv<3>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.oldfd as _, self.newfd as _, self.flags as _])
    }
}

pub struct EpollCreate1 {
    pub flags: c_int,
}

unsafe impl PassthroughAlloc for EpollCreate1 {
    const NUM: c_long = SYS_epoll_create1;

    type Argv = Argv<1>;
    type Ret = c_int;

    fn stage(self) -> Self::Argv {
        Argv([self.flags as _])
    }
}

pub struct Eventfd2 {
    pub initval: c_int,
    pub flags: c_int,
}

unsafe impl PassthroughAlloc for Eventfd2 {
    const NUM: c_long = SYS_eventfd2;

    type Argv = Argv<2>;
    type Ret = c_int;

    fn stage(self) -> Self::Argv {
        Argv([self.initval as _, self.flags as _])
    }
}

pub struct Exit {
    pub status: c_int,
}

unsafe impl PassthroughAlloc for Exit {
    const NUM: c_long = SYS_exit;

    type Argv = Argv<1>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.status as _])
    }
}

pub struct ExitGroup {
    pub status: c_int,
}

unsafe impl PassthroughAlloc for ExitGroup {
    const NUM: c_long = SYS_exit_group;

    type Argv = Argv<1>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.status as _])
    }
}

pub struct Listen {
    pub sockfd: c_int,
    pub backlog: c_int,
}

unsafe impl PassthroughAlloc for Listen {
    const NUM: c_long = SYS_listen;

    type Argv = Argv<2>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.sockfd as _, self.backlog as _])
    }
}

pub struct Socket {
    pub domain: c_int,
    pub typ: c_int,
    pub protocol: c_int,
}

unsafe impl PassthroughAlloc for Socket {
    const NUM: c_long = SYS_socket;

    type Argv = Argv<3>;
    type Ret = c_int;

    fn stage(self) -> Self::Argv {
        Argv([self.domain as _, self.typ as _, self.protocol as _])
    }
}

pub struct Sync;

unsafe impl PassthroughAlloc for Sync {
    const NUM: c_long = SYS_sync;

    type Argv = Argv<0>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}
