// SPDX-License-Identifier: Apache-2.0

use super::super::alloc::kind;
use super::super::types::Argv;
use super::super::{MaybeAlloc, UnstagedMaybeAlloc};
use super::PassthroughAlloc;
use crate::libc::{
    SYS_fcntl, EBADFD, EINVAL, F_GETFD, F_GETFL, F_SETFD, F_SETFL, O_APPEND, O_RDWR, O_WRONLY,
    STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO,
};
use crate::Result;

use core::ffi::{c_int, c_long};

pub struct Fcntl {
    pub fd: c_int,
    pub cmd: c_int,
    pub arg: c_int,
}

impl<'a> MaybeAlloc<'a, kind::Syscall> for Fcntl {
    type Alloc = AllocFcntl;

    #[inline]
    fn stage(self) -> Result<UnstagedMaybeAlloc<'a, kind::Syscall, Self::Alloc>> {
        match (self.fd, self.cmd) {
            (STDIN_FILENO, F_GETFL) => Ok(UnstagedMaybeAlloc::Stub(Ok(O_RDWR | O_APPEND))),
            (STDOUT_FILENO | STDERR_FILENO, F_GETFL) => Ok(UnstagedMaybeAlloc::Stub(Ok(O_WRONLY))),
            (STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO, _) => Err(EINVAL),
            (_, F_GETFD | F_SETFD | F_GETFL | F_SETFL) => {
                Ok(UnstagedMaybeAlloc::Alloc(AllocFcntl(self)))
            }
            (_, _) => Err(EBADFD),
        }
    }
}

pub struct AllocFcntl(Fcntl);

unsafe impl PassthroughAlloc for AllocFcntl {
    const NUM: c_long = SYS_fcntl;

    type Argv = Argv<3>;
    type Ret = c_int;

    #[inline]
    fn stage(self) -> Self::Argv {
        Argv([self.0.fd as _, self.0.cmd as _, self.0.arg as _])
    }
}
