// SPDX-License-Identifier: Apache-2.0

use super::types::Argv;
use super::Alloc;
use crate::guest::alloc::{Allocator, Collect, Collector, InOut, Output};
use crate::{Result, NULL};

use libc::{c_int, c_long, c_ulong};

pub struct Ioctl<'a> {
    pub fd: c_int,
    pub request: c_ulong,
    pub argp: Option<&'a mut [u8]>,
}

unsafe impl<'a> Alloc<'a> for Ioctl<'a> {
    const NUM: c_long = libc::SYS_ioctl;

    type Argv = Argv<4>;
    type Ret = c_int;

    type Staged = Option<InOut<'a, [u8], &'a mut [u8]>>;
    type Committed = Option<Output<'a, [u8], &'a mut [u8]>>;
    type Collected = Result<c_int>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let argp = if let Some(argp) = self.argp {
            InOut::stage_slice(alloc, argp).map(Some)?
        } else {
            None
        };
        let (argp_offset, argp_len) = argp
            .as_ref()
            .map_or((NULL, 0), |argp| (argp.offset(), argp.len()));
        Ok((
            Argv([self.fd as _, self.request as _, argp_offset, argp_len]),
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
