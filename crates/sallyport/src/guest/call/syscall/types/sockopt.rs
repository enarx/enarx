// SPDX-License-Identifier: Apache-2.0

use crate::guest::alloc::{Allocator, Input, Stage};
use crate::libc::EOVERFLOW;
use crate::Result;

use core::alloc::Layout;
use core::mem::{align_of, size_of};
use core::slice;

pub struct SockoptInput<'a>(pub &'a [u8]);

pub type StagedSockoptInput<'a> = Input<'a, [u8], &'a [u8]>;

impl<'a> From<&'a [u8]> for SockoptInput<'a> {
    #[inline]
    fn from(opt: &'a [u8]) -> Self {
        Self(opt)
    }
}

impl<'a, T> From<&'a T> for SockoptInput<'a> {
    #[inline]
    fn from(opt: &'a T) -> Self {
        debug_assert!(align_of::<T>() <= align_of::<usize>());
        Self(unsafe { slice::from_raw_parts(opt as *const _ as _, size_of::<T>()) })
    }
}

impl<'a> Stage<'a> for SockoptInput<'a> {
    type Item = StagedSockoptInput<'a>;

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        let layout =
            Layout::from_size_align(self.0.len(), align_of::<usize>()).map_err(|_| EOVERFLOW)?;
        let opt = alloc.allocate_input_layout(layout)?;
        Ok(unsafe { Input::new_unchecked(opt, self.0) })
    }
}
