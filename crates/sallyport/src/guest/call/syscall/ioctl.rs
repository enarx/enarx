// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collect, Collector, InOut, Output};
use crate::guest::call::alloc::kind;
use crate::guest::call::{MaybeAlloc, UnstagedMaybeAlloc};
use crate::libc::{
    self, SYS_ioctl, EBADFD, EINVAL, ENOTTY, FIONBIO, FIONREAD, STDERR_FILENO, STDIN_FILENO,
    STDOUT_FILENO, TIOCGWINSZ,
};
use crate::{Result, NULL};

use core::ffi::{c_int, c_long};

pub struct Ioctl<'a> {
    pub fd: c_int,
    pub request: libc::Ioctl,
    pub argp: Option<&'a mut [u8]>,
}

impl<'a> MaybeAlloc<'a, kind::Syscall> for Ioctl<'a> {
    type Alloc = AllocIoctl<'a>;

    #[inline]
    fn stage(self) -> Result<UnstagedMaybeAlloc<'a, kind::Syscall, Self::Alloc>> {
        match (self.fd, self.request) {
            (STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO, TIOCGWINSZ) => {
                // the keep has no tty
                Ok(UnstagedMaybeAlloc::Stub(Err(ENOTTY)))
            }
            (STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO, _) => {
                Ok(UnstagedMaybeAlloc::Stub(Err(EINVAL)))
            }
            (_, FIONBIO | FIONREAD) => Ok(UnstagedMaybeAlloc::Alloc(AllocIoctl(self))),
            _ => Ok(UnstagedMaybeAlloc::Stub(Err(EBADFD))),
        }
    }
}

pub struct AllocIoctl<'a>(Ioctl<'a>);

unsafe impl<'a> Alloc<'a> for AllocIoctl<'a> {
    const NUM: c_long = SYS_ioctl;

    type Argv = Argv<4>;
    type Ret = c_int;

    type Staged = Option<InOut<'a, [u8], &'a mut [u8]>>;
    type Committed = Option<Output<'a, [u8], &'a mut [u8]>>;
    type Collected = Result<c_int>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let argp = if let Some(argp) = self.0.argp {
            InOut::stage_slice(alloc, argp).map(Some)?
        } else {
            None
        };
        let (argp_offset, argp_len) = argp
            .as_ref()
            .map_or((NULL, 0), |argp| (argp.offset(), argp.len()));
        Ok((
            Argv([self.0.fd as _, self.0.request as _, argp_offset, argp_len]),
            argp,
        ))
    }

    fn collect(
        argp: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        argp.collect(col);
        ret
    }
}
