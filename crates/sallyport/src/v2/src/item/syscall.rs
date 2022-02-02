// SPDX-License-Identifier: Apache-2.0

use core::mem::size_of;

/// Payload of an [`Item`](super::Item) of [`Kind::Syscall`](super::Kind::Syscall).
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Payload {
    pub num: usize,
    pub argv: [usize; 6],
    pub ret: [usize; 2],
}

pub(crate) const USIZE_COUNT: usize = size_of::<Payload>() / size_of::<usize>();

impl From<&mut [usize; USIZE_COUNT]> for &mut Payload {
    #[inline]
    fn from(buf: &mut [usize; USIZE_COUNT]) -> Self {
        debug_assert_eq!(size_of::<Payload>(), USIZE_COUNT * size_of::<usize>());
        unsafe { &mut *(buf as *mut _ as *mut _) }
    }
}
