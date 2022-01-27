// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific types.

use crate::guest::alloc::{
    Allocator, Collect, Collector, Commit, Committer, InOut, Input, Output, Stage,
};
use crate::{Result, NULL};
use core::alloc::Layout;
use core::mem::{align_of, size_of};
use core::slice;

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

pub struct SockaddrInput<'a>(pub &'a [u8]);

pub type StagedSockaddrInput<'a> = Input<'a, [u8], &'a [u8]>;

impl<'a> From<&'a [u8]> for SockaddrInput<'a> {
    #[inline]
    fn from(addr: &'a [u8]) -> Self {
        Self(addr)
    }
}

impl<'a, T> From<&'a T> for SockaddrInput<'a> {
    #[inline]
    fn from(addr: &'a T) -> Self {
        debug_assert!(align_of::<T>() <= align_of::<sockaddr_storage>());
        Self(unsafe { slice::from_raw_parts(addr as *const _ as _, size_of::<T>()) })
    }
}

impl<'a> Stage<'a> for SockaddrInput<'a> {
    type Item = StagedSockaddrInput<'a>;

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        let layout = Layout::from_size_align(self.0.len(), align_of::<sockaddr_storage>())
            .map_err(|_| EOVERFLOW)?;
        let addr = alloc.allocate_input_layout(layout)?;
        Ok(unsafe { Input::new_unchecked(addr, self.0) })
    }
}

pub struct SockaddrOutput<'a> {
    pub addr: &'a mut [u8],
    pub addrlen: &'a mut socklen_t,
}

impl<'a> From<(&'a mut [u8], &'a mut socklen_t)> for SockaddrOutput<'a> {
    #[inline]
    fn from((addr, addrlen): (&'a mut [u8], &'a mut socklen_t)) -> Self {
        debug_assert_eq!(addr.len(), *addrlen as _);
        Self::new(addr, addrlen)
    }
}

impl<'a, T> From<(&'a mut T, &'a mut socklen_t)> for SockaddrOutput<'a> {
    #[inline]
    fn from((addr, addrlen): (&'a mut T, &'a mut socklen_t)) -> Self {
        debug_assert!(align_of::<T>() <= align_of::<sockaddr_storage>());
        debug_assert_eq!(size_of::<T>(), *addrlen as _);
        Self::new(
            unsafe { slice::from_raw_parts_mut(addr as *const _ as _, size_of::<T>()) },
            addrlen,
        )
    }
}

impl<'a> SockaddrOutput<'a> {
    #[inline]
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

    #[inline]
    fn commit(self, com: &impl Committer) -> Self::Item {
        Self::Item {
            addr: self.addr,
            addrlen: self.addrlen.commit(com),
        }
    }
}

impl<'a> Collect for CommittedSockaddrOutput<'a> {
    type Item = ();

    #[inline]
    fn collect(self, col: &impl Collector) {
        let addrlen = *self.addrlen.collect(col);
        let len = self.addr.len().min(addrlen as _);
        unsafe { self.addr.collect_range(col, 0..len) };
    }
}
