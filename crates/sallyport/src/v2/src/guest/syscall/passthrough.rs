// SPDX-License-Identifier: Apache-2.0

use super::types::Argv;
use crate::guest::alloc::PassthroughSyscall;

use libc::{c_int, c_long};

pub struct Close {
    pub fd: c_int,
}

unsafe impl PassthroughSyscall for Close {
    const NUM: c_long = libc::SYS_close;

    type Argv = Argv<1>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.fd as _])
    }
}

pub struct Dup {
    pub oldfd: c_int,
}

unsafe impl PassthroughSyscall for Dup {
    const NUM: c_long = libc::SYS_dup;

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

unsafe impl PassthroughSyscall for Dup2 {
    const NUM: c_long = libc::SYS_dup2;

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

unsafe impl PassthroughSyscall for Dup3 {
    const NUM: c_long = libc::SYS_dup3;

    type Argv = Argv<3>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.oldfd as _, self.newfd as _, self.flags as _])
    }
}

pub struct EpollCreate1 {
    pub flags: c_int,
}

unsafe impl PassthroughSyscall for EpollCreate1 {
    const NUM: c_long = libc::SYS_epoll_create1;

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

unsafe impl PassthroughSyscall for Eventfd2 {
    const NUM: c_long = libc::SYS_eventfd2;

    type Argv = Argv<2>;
    type Ret = c_int;

    fn stage(self) -> Self::Argv {
        Argv([self.initval as _, self.flags as _])
    }
}

pub struct Exit {
    pub status: c_int,
}

unsafe impl PassthroughSyscall for Exit {
    const NUM: c_long = libc::SYS_exit;

    type Argv = Argv<1>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([self.status as _])
    }
}

pub struct ExitGroup {
    pub status: c_int,
}

unsafe impl PassthroughSyscall for ExitGroup {
    const NUM: c_long = libc::SYS_exit_group;

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

unsafe impl PassthroughSyscall for Listen {
    const NUM: c_long = libc::SYS_listen;

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

unsafe impl PassthroughSyscall for Socket {
    const NUM: c_long = libc::SYS_socket;

    type Argv = Argv<3>;
    type Ret = c_int;

    fn stage(self) -> Self::Argv {
        Argv([self.domain as _, self.typ as _, self.protocol as _])
    }
}

pub struct Sync;

unsafe impl PassthroughSyscall for Sync {
    const NUM: c_long = libc::SYS_sync;

    type Argv = Argv<0>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}
