// SPDX-License-Identifier: Apache-2.0

use super::Argv;
use crate::guest::alloc::{
    Allocator, Collect, Collector, Commit, CommittedSyscall, Committer, Stage, StagedSyscall,
    Syscall,
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

unsafe impl<'a> Syscall<'a> for Alloc {
    const NUM: c_long = libc::SYS_fcntl;

    type Argv = Argv<3>;
    type Ret = super::Result<c_int>;

    type Staged = ();
    type Committed = ();
    type Collected = Result<c_int>;

    fn stage(self, _: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        Ok((Argv([self.0.fd as _, self.0.cmd as _, self.0.arg as _]), ()))
    }

    fn collect(_: Self::Committed, ret: Self::Ret, _: &impl Collector) -> Self::Collected {
        ret.into()
    }
}

pub enum StagedFcntl<'a> {
    Alloc(StagedSyscall<'a, Alloc>),
    Stub(c_int),
}

impl<'a> Stage<'a> for Fcntl {
    type Item = StagedFcntl<'a>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        match (self.fd, self.cmd) {
            (STDIN_FILENO, F_GETFL) => Ok(StagedFcntl::Stub(O_RDWR | O_APPEND)),
            (STDOUT_FILENO | STDERR_FILENO, F_GETFL) => Ok(StagedFcntl::Stub(O_WRONLY)),
            (STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO, _) => Err(EINVAL),
            (_, F_GETFD | F_SETFD | F_GETFL | F_SETFL) => {
                Stage::stage(Alloc(self), alloc).map(StagedFcntl::Alloc)
            }
            (_, _) => Err(EBADFD),
        }
    }
}

pub enum CommittedFcntl<'a> {
    Alloc(CommittedSyscall<'a, Alloc>),
    Stub(c_int),
}

impl<'a> Commit for StagedFcntl<'a> {
    type Item = CommittedFcntl<'a>;

    fn commit(self, com: &impl Committer) -> CommittedFcntl<'a> {
        match self {
            StagedFcntl::Alloc(syscall) => CommittedFcntl::Alloc(syscall.commit(com)),
            StagedFcntl::Stub(val) => CommittedFcntl::Stub(val),
        }
    }
}

impl<'a> Collect for CommittedFcntl<'a> {
    type Item = Result<c_int>;

    fn collect(self, col: &impl Collector) -> Self::Item {
        match self {
            CommittedFcntl::Alloc(syscall) => Collect::collect(syscall, col),
            CommittedFcntl::Stub(val) => Ok(val),
        }
    }
}
