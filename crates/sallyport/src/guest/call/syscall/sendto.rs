// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::types::{SockaddrInput, StagedBytesInput};
use super::Alloc;
use crate::guest::alloc::{Allocator, Collector, Commit, Committer, Input, Stage};
use crate::libc::SYS_sendto;
use crate::Result;

use core::ffi::{c_int, c_long, c_size_t};

pub struct Sendto<'a, T> {
    pub sockfd: c_int,
    pub buf: &'a [u8],
    pub flags: c_int,
    pub dest_addr: T,
}

pub struct StagedSendto<'a> {
    dest_addr: Input<'a, [u8], &'a [u8]>,
    buf: Input<'a, [u8], &'a [u8]>,
}

impl<'a> Commit for StagedSendto<'a> {
    type Item = c_size_t;

    fn commit(self, com: &impl Committer) -> Self::Item {
        self.dest_addr.commit(com);
        StagedBytesInput(self.buf).commit(com)
    }
}

unsafe impl<'a, T: Into<SockaddrInput<'a>>> Alloc<'a> for Sendto<'a, T> {
    const NUM: c_long = SYS_sendto;

    type Argv = Argv<6>;
    type Ret = c_size_t;

    type Staged = StagedSendto<'a>;
    type Committed = c_size_t;
    type Collected = Option<Result<c_size_t>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let dest_addr = self.dest_addr.into().stage(alloc)?;
        let (buf, _) = Input::stage_slice_max(alloc, self.buf)?;
        Ok((
            Argv([
                self.sockfd as _,
                buf.offset(),
                buf.len(),
                self.flags as _,
                dest_addr.offset(),
                dest_addr.len(),
            ]),
            StagedSendto { dest_addr, buf },
        ))
    }

    fn collect(
        len: Self::Committed,
        ret: Result<Self::Ret>,
        _: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret > len => None,
            res @ Ok(_) => Some(res),
            err => Some(err),
        }
    }
}
