// SPDX-License-Identifier: Apache-2.0

//! System call item definitions

use core::ffi::c_int;
use core::mem::size_of;

/// Payload of an [`Item`](super::Item) of [`Kind::Syscall`](super::Kind::Syscall).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

// arch_prctl syscalls not available in the libc crate as of version 0.2.69
/// missing in libc
pub const ARCH_SET_GS: c_int = 0x1001;
/// missing in libc
pub const ARCH_SET_FS: c_int = 0x1002;
/// missing in libc
pub const ARCH_GET_FS: c_int = 0x1003;
/// missing in libc
pub const ARCH_GET_GS: c_int = 0x1004;

// [`libc::sigaction`] is not in the format used by the kernel.
/// sigaction as expected by the kernel.
#[allow(non_camel_case_types)] // follow `libc` conventions
pub type sigaction = [u64; 4];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_size() {
        assert_eq!(size_of::<Payload>(), USIZE_COUNT * size_of::<usize>())
    }
}
