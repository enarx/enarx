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

/// `get_attestation` syscall number
///
/// See <https://github.com/enarx/enarx-keepldr/issues/31>
#[allow(dead_code)]
pub const SYS_ENARX_GETATT: i64 = 0xEA01;

/// Enarx syscall extension: get [`MemInfo`] from the host
#[allow(dead_code)]
pub const SYS_ENARX_MEM_INFO: i64 = 0xEA02;

/// Enarx syscall extension: request an additional memory region
#[allow(dead_code)]
pub const SYS_ENARX_BALLOON_MEMORY: i64 = 0xEA03;

/// Enarx syscall extension: CPUID
#[allow(dead_code)]
pub const SYS_ENARX_CPUID: i64 = 0xEA04;

/// Enarx syscall extension: Resume an enclave after an asynchronous exit
// Keep in sync with shim-sgx/src/start.S
#[allow(dead_code)]
pub const SYS_ENARX_ERESUME: i64 = -1;

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

// arch_prctl syscalls not available in the libc crate as of version 0.2.69
/// missing in libc
pub const ARCH_SET_GS: libc::c_int = 0x1001;
/// missing in libc
pub const ARCH_SET_FS: libc::c_int = 0x1002;
/// missing in libc
pub const ARCH_GET_FS: libc::c_int = 0x1003;
/// missing in libc
pub const ARCH_GET_GS: libc::c_int = 0x1004;

/// Basic information about the host memory, the shim requests
/// from the loader via the [`SYS_ENARX_MEM_INFO`] syscall
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct MemInfo {
    /// Number of memory slot available for ballooning
    ///
    /// KVM only has a limited number of memory ballooning slots, which varies by technology and kernel version.
    /// Knowing this number helps the shim allocator to decide how much memory to allocate for each slot.
    pub mem_slots: usize,
}
