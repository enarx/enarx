// SPDX-License-Identifier: Apache-2.0

use crate::Error;

use core::convert::TryFrom;
use libc::EINVAL;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(usize)]
pub enum Kind {
    End = 0x00,

    Syscall = 0x01,
}

impl TryFrom<usize> for Kind {
    type Error = Error;

    #[inline]
    fn try_from(kind: usize) -> Result<Self, Self::Error> {
        match kind {
            kind if kind == Kind::End as _ => Ok(Kind::End),
            kind if kind == Kind::Syscall as _ => Ok(Kind::Syscall),
            _ => Err(EINVAL),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Header {
    pub size: usize,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Syscall {
    pub num: usize,
    pub argv: [usize; 6],
    pub ret: [usize; 2],
}
