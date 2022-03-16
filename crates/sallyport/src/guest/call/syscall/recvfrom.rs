// SPDX-License-Identifier: Apache-2.0

use super::super::types::Argv;
use super::types::{CommittedSockaddrOutput, SockaddrOutput, StagedSockaddrOutput};
use super::Alloc;
use crate::guest::alloc::{Allocator, Collect, Collector, Output, Stage};
use crate::libc::SYS_recvfrom;
use crate::Result;

use core::ffi::{c_int, c_long, c_size_t};

pub struct Recvfrom<'a, T> {
    pub sockfd: c_int,
    pub buf: &'a mut [u8],
    pub flags: c_int,
    pub src_addr: T,
}

unsafe impl<'a, T: Into<SockaddrOutput<'a>>> Alloc<'a> for Recvfrom<'a, T> {
    const NUM: c_long = SYS_recvfrom;

    type Argv = Argv<6>;
    type Ret = c_size_t;

    type Staged = (
        Output<'a, [u8], &'a mut [u8]>, // buf
        StagedSockaddrOutput<'a>,
    );
    type Committed = (
        Output<'a, [u8], &'a mut [u8]>, // buf
        CommittedSockaddrOutput<'a>,
    );
    type Collected = Option<Result<c_size_t>>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let src_addr = self.src_addr.into().stage(alloc)?;
        let (buf, _) = Output::stage_slice_max(alloc, self.buf)?;
        Ok((
            Argv([
                self.sockfd as _,
                buf.offset(),
                buf.len(),
                self.flags as _,
                src_addr.addr.offset(),
                src_addr.addrlen.offset(),
            ]),
            (buf, src_addr),
        ))
    }

    fn collect(
        (buf, src_addr): Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        match ret {
            Ok(ret) if ret > buf.len() => None,
            res @ Ok(ret) => {
                unsafe { buf.collect_range(col, 0..ret) };
                src_addr.collect(col);
                Some(res)
            }
            err => Some(err),
        }
    }
}
