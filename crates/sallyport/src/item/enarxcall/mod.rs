// SPDX-License-Identifier: Apache-2.0

//! Enarx call item definitions

pub mod sev;
pub mod sgx;

use core::mem::size_of;

/// `get_attestation` syscall number used by the shim.
///
/// See <https://github.com/enarx/enarx/issues/966>
#[allow(dead_code)]
pub const SYS_GETATT: i64 = 0xEA01;

/// `get_key` syscall number used by the shim.
///
/// See <https://github.com/enarx/enarx/issues/2110>
#[allow(dead_code)]
pub const SYS_GETKEY: i64 = 0xEA02;

/// Payload of an [`Item`](super::Item) of [`Kind::Enarxcall`](super::Kind::Enarxcall).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
/// Number of an [`Item`](super::Item) of [`Kind::Enarxcall`](super::Kind::Enarxcall).
pub enum Number {
    /// MemInfo request call number.
    MemInfo = 0x00,

    /// Memory ballooning request call number.
    BalloonMemory = 0x01,

    /// Cpuid instruction call number.
    Cpuid = 0x02,

    /// SGX quote request call number.
    GetSgxQuote = 0x03,

    /// [SGX `TargetInfo`](sgx::TargetInfo) request call number.
    GetSgxTargetInfo = 0x04,

    /// SGX quote size request call number.
    GetSgxQuoteSize = 0x05,

    /// SNP VCEK request call number.
    GetSnpVcek = 0x06,

    /// Notify the host about `mmap()`.
    MmapHost = 0x07,

    /// Notify the host about `mprotect()`.
    MprotectHost = 0x08,

    /// Notify the host about `munmap()`.
    MunmapHost = 0x09,

    /// Trim SGX pages call number.
    SgxModifyPageType = 0x10,

    /// Park the current thread
    Park = 0x11,

    /// UnPark all parked threads
    UnPark = 0x12,

    /// Spawn a new thread
    Spawn = 0x13,

    /// Register a new sallyport block
    NewSallyport = 0x14,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_size() {
        assert_eq!(size_of::<Payload>(), USIZE_COUNT * size_of::<usize>())
    }

    #[test]
    fn tech_assignments() {
        assert_ne!(sev::TECH, sgx::TECH);
    }
}
