// SPDX-License-Identifier: Apache-2.0

use super::Argv;
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

pub struct Sync;

unsafe impl PassthroughSyscall for Sync {
    const NUM: c_long = libc::SYS_sync;

    type Argv = Argv<0>;
    type Ret = ();

    fn stage(self) -> Self::Argv {
        Argv([])
    }
}
