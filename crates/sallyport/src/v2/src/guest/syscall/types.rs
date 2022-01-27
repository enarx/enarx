// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific types.

use crate::guest::alloc::{Allocator, Collect, Commit, InOut, Output, Stage};
use crate::{Result, NULL};
use core::alloc::Layout;
use core::mem::align_of;

use libc::{sockaddr_storage, socklen_t, EOVERFLOW};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Argv<const N: usize>(pub [usize; N]);

impl From<Argv<0>> for [usize; 6] {
    #[inline]
    fn from(_: Argv<0>) -> Self {
        [NULL, NULL, NULL, NULL, NULL, NULL]
    }
}

impl From<Argv<1>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<1>) -> Self {
        [argv.0[0], NULL, NULL, NULL, NULL, NULL]
    }
}

impl From<Argv<2>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<2>) -> Self {
        [argv.0[0], argv.0[1], NULL, NULL, NULL, NULL]
    }
}

impl From<Argv<3>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<3>) -> Self {
        [argv.0[0], argv.0[1], argv.0[2], NULL, NULL, NULL]
    }
}

impl From<Argv<4>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<4>) -> Self {
        [argv.0[0], argv.0[1], argv.0[2], argv.0[3], NULL, NULL]
    }
}

impl From<Argv<5>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<5>) -> Self {
        [argv.0[0], argv.0[1], argv.0[2], argv.0[3], argv.0[4], NULL]
    }
}

impl From<Argv<6>> for [usize; 6] {
    #[inline]
    fn from(argv: Argv<6>) -> Self {
        argv.0
    }
}

pub struct SockaddrOutput<'a> {
    pub addr: &'a mut [u8],
    pub addrlen: &'a mut socklen_t,
}

impl<'a> SockaddrOutput<'a> {
    pub fn new(addr: &'a mut [u8], addrlen: &'a mut socklen_t) -> Self {
        Self { addr, addrlen }
    }
}

pub struct StagedSockaddrOutput<'a> {
    pub addr: Output<'a, [u8], &'a mut [u8]>,
    pub addrlen: InOut<'a, socklen_t, &'a mut socklen_t>,
}

pub struct CommittedSockaddrOutput<'a> {
    pub addr: Output<'a, [u8], &'a mut [u8]>,
    pub addrlen: Output<'a, socklen_t, &'a mut socklen_t>,
}

impl<'a> Stage<'a> for SockaddrOutput<'a> {
    type Item = StagedSockaddrOutput<'a>;

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        let layout = Layout::from_size_align(self.addr.len(), align_of::<sockaddr_storage>())
            .map_err(|_| EOVERFLOW)?;
        let addr = alloc.allocate_output_layout(layout)?;
        let addrlen = InOut::stage(alloc, self.addrlen)?;
        Ok(Self::Item {
            addr: unsafe { Output::new_unchecked(addr, self.addr) },
            addrlen,
        })
    }
}

impl<'a> Commit for StagedSockaddrOutput<'a> {
    type Item = CommittedSockaddrOutput<'a>;

    fn commit(self, com: &impl crate::guest::alloc::Committer) -> Self::Item {
        Self::Item {
            addr: self.addr,
            addrlen: self.addrlen.commit(com),
        }
    }
}

impl<'a> Collect for CommittedSockaddrOutput<'a> {
    type Item = ();

    fn collect(self, col: &impl crate::guest::alloc::Collector) {
        let addrlen = *self.addrlen.collect(col);
        let len = self.addr.len().min(addrlen as _);
        unsafe { self.addr.collect_range(col, 0..len) };
    }
}
