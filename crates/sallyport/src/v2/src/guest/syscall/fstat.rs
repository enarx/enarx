// SPDX-License-Identifier: Apache-2.0

use crate::guest::alloc::{Allocator, Collect, Collector, CommitPassthrough, Stage};
use crate::Result;

use core::mem;
use libc::{c_int, stat, EBADFD, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO, S_IFIFO};

pub struct Fstat<'a> {
    pub fd: c_int,
    pub statbuf: &'a mut stat,
}

impl<'a> Stage<'a> for Fstat<'a> {
    type Item = Self;

    fn stage(self, _: &mut impl Allocator) -> Result<Self::Item> {
        match self.fd {
            STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO => Ok(self),
            // TODO: Support `fstat` on files.
            // https://github.com/enarx/sallyport/issues/45
            _ => Err(EBADFD),
        }
    }
}

impl<'a> CommitPassthrough for Fstat<'a> {}

impl<'a> Collect for Fstat<'a> {
    type Item = Result<()>;

    fn collect(self, _: &impl Collector) -> Self::Item {
        #[allow(clippy::integer_arithmetic)]
        const fn makedev(x: u64, y: u64) -> u64 {
            (((x) & 0xffff_f000u64) << 32)
                | (((x) & 0x0000_0fffu64) << 8)
                | (((y) & 0xffff_ff00u64) << 12)
                | ((y) & 0x0000_00ffu64)
        }

        let mut p: stat = unsafe { mem::zeroed() };

        p.st_dev = makedev(
            0,
            match self.fd {
                0 => 0x19,
                _ => 0xc,
            },
        );
        p.st_ino = 3;
        p.st_mode = S_IFIFO | 0o600;
        p.st_nlink = 1;
        p.st_uid = 1000;
        p.st_gid = 5;
        p.st_blksize = 4096;
        p.st_blocks = 0;
        p.st_rdev = makedev(0x88, 0);
        p.st_size = 0;

        p.st_atime = 1_579_507_218 /* 2020-01-21T11:45:08.467721685+0100 */;
        p.st_atime_nsec = 0;
        p.st_mtime = 1_579_507_218 /* 2020-01-21T11:45:07.467721685+0100 */;
        p.st_mtime_nsec = 0;
        p.st_ctime = 1_579_507_218 /* 2020-01-20T09:00:18.467721685+0100 */;
        p.st_ctime_nsec = 0;

        *self.statbuf = p;
        Ok(())
    }
}
