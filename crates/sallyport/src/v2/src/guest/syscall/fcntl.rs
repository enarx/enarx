// SPDX-License-Identifier: Apache-2.0

use super::types::Argv;
use crate::guest::alloc::{
    kind, Allocator, Call, MaybeAlloc, PassthroughSyscall, StagedMaybeAlloc,
};
use crate::Result;

use libc::{
    c_int, c_long, EBADFD, EINVAL, F_GETFD, F_GETFL, F_SETFD, F_SETFL, O_APPEND, O_RDWR, O_WRONLY,
    STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO,
};

pub struct Fcntl {
    pub fd: c_int,
    pub cmd: c_int,
    pub arg: c_int,
}

pub struct Alloc(Fcntl);

unsafe impl PassthroughSyscall for Alloc {
    const NUM: c_long = libc::SYS_fcntl;

    type Argv = Argv<3>;
    type Ret = c_int;

    #[inline]
    fn stage(self) -> Self::Argv {
        Argv([self.0.fd as _, self.0.cmd as _, self.0.arg as _])
    }
}

impl<'a> MaybeAlloc<'a, kind::Syscall, Alloc> for Fcntl {
    #[inline]
    fn stage(
        self,
        alloc: &mut impl Allocator,
    ) -> Result<StagedMaybeAlloc<'a, kind::Syscall, Alloc>> {
        match (self.fd, self.cmd) {
            (STDIN_FILENO, F_GETFL) => Ok(StagedMaybeAlloc::Stub(Ok(O_RDWR | O_APPEND))),
            (STDOUT_FILENO | STDERR_FILENO, F_GETFL) => Ok(StagedMaybeAlloc::Stub(Ok(O_WRONLY))),
            (STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO, _) => Err(EINVAL),
            (_, F_GETFD | F_SETFD | F_GETFL | F_SETFL) => {
                Call::stage(Alloc(self), alloc).map(StagedMaybeAlloc::Alloc)
            }
            (_, _) => Err(EBADFD),
        }
    }
}
