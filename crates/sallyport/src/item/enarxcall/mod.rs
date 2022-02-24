// SPDX-License-Identifier: Apache-2.0

use core::mem::size_of;

/// `get_attestation` syscall number used by the shim.
///
/// See <https://github.com/enarx/enarx-keepldr/issues/31>
#[allow(dead_code)]
pub const SYS_GETATT: i64 = 0xEA01;

/// Payload of an [`Item`](super::Item) of [`Kind::Enarxcall`](super::Kind::Enarxcall).
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Payload {
    pub num: Number,
    pub argv: [usize; 4],
    pub ret: usize,
}

pub(crate) const USIZE_COUNT: usize = size_of::<Payload>() / size_of::<usize>();

impl From<&mut [usize; USIZE_COUNT]> for &mut Payload {
    #[inline]
    fn from(buf: &mut [usize; USIZE_COUNT]) -> Self {
        debug_assert_eq!(size_of::<Payload>(), USIZE_COUNT * size_of::<usize>());
        unsafe { &mut *(buf as *mut _ as *mut _) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(usize)]
/// Number of an [`Item`](super::Item) of [`Kind::Enarxcall`](super::Kind::Enarxcall).
pub enum Number {
}

/// `get_attestation` technology return value
///
/// See <https://github.com/enarx/enarx-keepldr/issues/31>
#[allow(dead_code)]
pub const SEV_TECH: usize = 1;

/// `get_attestation` technology return value
///
/// See <https://github.com/enarx/enarx-keepldr/issues/31>
#[allow(dead_code)]
pub const SGX_TECH: usize = 2;

/// Size in bytes of expected SGX Quote
// TODO: Determine length of Quote of PCK cert type
#[allow(dead_code)]
pub const SGX_QUOTE_SIZE: usize = 4598;

/// Size in bytes of expected SGX QE TargetInfo
#[allow(dead_code)]
pub const SGX_TI_SIZE: usize = 512;

/// Dummy value returned when daemon to return SGX TargetInfo is
/// not available on the system.
#[allow(dead_code)]
pub const SGX_DUMMY_TI: [u8; SGX_TI_SIZE] = [32u8; SGX_TI_SIZE];

/// Dummy value returned when daemon to return SGX Quote is not
/// available on the system.
#[allow(dead_code)]
pub const SGX_DUMMY_QUOTE: [u8; SGX_QUOTE_SIZE] = [44u8; SGX_QUOTE_SIZE];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_size() {
        assert_eq!(size_of::<Payload>(), USIZE_COUNT * size_of::<usize>())
    }
}
